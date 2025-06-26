package server

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/nadav-yo/mcp-gateway/internal/client"
	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/handlers"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
	"github.com/rs/zerolog"
)

// Server represents the MCP gateway server
type Server struct {
	config         *config.Config
	db             *database.DB
	upgrader       websocket.Upgrader
	tools          map[string]*types.Tool
	resources      map[string]*types.Resource	
	clients        map[string]*client.MCPClient
	prompts        map[string]*types.Prompt  // Store prompts from upstream servers (but don't expose locally)
	clientsByID    map[int64]*client.MCPClient
	mu             sync.RWMutex
	stats          types.GatewayStats
	upstreamHandler *handlers.UpstreamHandler
	authHandler     *handlers.AuthHandler
	logger         zerolog.Logger
	ctx            context.Context
	cancel         context.CancelFunc
}

	
func (s *Server) Shutdown() error {
	s.logger.Info().Msg("Shutting down MCP Gateway Server...")
	
	// Cancel the server context to signal shutdown to all goroutines
	s.cancel()
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Close all upstream connections
	for name, mcpClient := range s.clients {
		if err := mcpClient.Close(); err != nil {
			s.logger.Error().
				Err(err).
				Str("upstream", name).
				Msg("Error closing connection to upstream")
		}
	}
	
	s.logger.Info().Msg("MCP Gateway Server shutdown complete")
	return nil
}
// New creates a new MCP gateway server instance
func New(cfg *config.Config, db *database.DB) *Server {
	authHandler := handlers.NewAuthHandler(db)
	ctx, cancel := context.WithCancel(context.Background())
	
	server := &Server{
		config: cfg,
		db:     db,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
		},
		tools:       make(map[string]*types.Tool),
		resources:   make(map[string]*types.Resource),
		prompts:     make(map[string]*types.Prompt),
		clients:     make(map[string]*client.MCPClient),
		clientsByID: make(map[int64]*client.MCPClient),
		authHandler: authHandler,
		logger:      logger.GetLogger("server"),
		ctx:         ctx,
		cancel:      cancel,
	}
	
	// Create upstream handler with server reference
	server.upstreamHandler = handlers.NewUpstreamHandler(db, server)
	
	return server
}

// Router returns the HTTP router
func (s *Server) Router() http.Handler {
	r := mux.NewRouter()
	
	// Register authentication routes first (includes public login endpoint)
	s.authHandler.RegisterRoutes(r)

	// Apply authentication middleware to MCP endpoints if auth is enabled
	if s.config.Security.EnableAuth {		
		// Protected MCP endpoints
		mcpRouter := r.NewRoute().Subrouter()
		mcpRouter.Use(s.authHandler.AuthMiddleware)
		
		// SSE endpoint for MCP communication (VS Code uses this)
		mcpRouter.HandleFunc("/", s.handleSSE).Methods("GET", "POST")
		
		// WebSocket endpoint for MCP communication
		mcpRouter.HandleFunc("/mcp", s.handleWebSocket)
		
		// HTTP endpoints for MCP over HTTP
		mcpRouter.HandleFunc("/mcp/http", s.handleHTTP).Methods("POST")
		
		// Gateway-specific endpoints
		mcpRouter.HandleFunc("/gateway/status", s.handleGatewayStatus).Methods("GET")
		mcpRouter.HandleFunc("/gateway/upstream", s.handleUpstreamServers).Methods("GET")
		mcpRouter.HandleFunc("/gateway/stats", s.handleGatewayStats).Methods("GET")
		mcpRouter.HandleFunc("/gateway/refresh", s.handleRefreshConnections).Methods("POST")
		
		// Register CRUD API routes with auth
		s.upstreamHandler.RegisterRoutes(mcpRouter)
	} else {
		// Unprotected endpoints when auth is disabled
		// SSE endpoint for MCP communication (VS Code uses this)
		r.HandleFunc("/", s.handleSSE).Methods("GET", "POST")
		
		// WebSocket endpoint for MCP communication
		r.HandleFunc("/mcp", s.handleWebSocket)
		
		// HTTP endpoints for MCP over HTTP
		r.HandleFunc("/mcp/http", s.handleHTTP).Methods("POST")
		
		// Gateway-specific endpoints
		r.HandleFunc("/gateway/status", s.handleGatewayStatus).Methods("GET")
		r.HandleFunc("/gateway/upstream", s.handleUpstreamServers).Methods("GET")
		r.HandleFunc("/gateway/stats", s.handleGatewayStats).Methods("GET")
		r.HandleFunc("/gateway/refresh", s.handleRefreshConnections).Methods("POST")
		
		// Register CRUD API routes without auth
		s.upstreamHandler.RegisterRoutes(r)
	}

	r.HandleFunc("/admin", s.handleAdminPanel).Methods("GET")
	r.HandleFunc("/health", s.handleHealth).Methods("GET")
	r.HandleFunc("/info", s.handleInfo).Methods("GET")
	// Static file serving for CSS and JS files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/"))))
	
	return r
}

// handleWebSocket handles WebSocket connections for MCP protocol
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	defer conn.Close()

	s.logger.Info().Msg("New WebSocket connection established")

	// Set up a channel to handle graceful shutdown
	done := make(chan struct{})
	defer close(done)

	// Goroutine to handle reading messages
	go func() {
		defer func() {
			select {
			case done <- struct{}{}:
			default:
			}
		}()
		
		for {
			var req types.MCPRequest
			if err := conn.ReadJSON(&req); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					s.logger.Error().Err(err).Msg("WebSocket error")
				}
				return
			}

			response := s.handleMCPRequest(&req)
			
			if err := conn.WriteJSON(response); err != nil {
				s.logger.Error().Err(err).Msg("WebSocket write error")
				return
			}
		}
	}()

	// Wait for either connection to close or server to shutdown
	select {
	case <-done:
		// Connection closed normally
	case <-s.ctx.Done():
		// Server shutting down
		s.logger.Info().Msg("WebSocket connection closing due to server shutdown")
	}
}

// handleHTTP handles HTTP requests for MCP protocol
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var req types.MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	response := s.handleMCPRequest(&req)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error().Err(err).Msg("Failed to encode response")
	}
}

// handleSSE handles Server-Sent Events for MCP protocol (used by VS Code)
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Handle SSE connection setup for VS Code
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")
		
		// For VS Code MCP, we need to handle the connection differently
		// VS Code expects to be able to send messages via POST and receive responses
		// The GET request is just to establish the SSE connection
		
		// Create a channel to keep the connection alive
		done := make(chan bool)
		
		// Set up a goroutine to keep connection alive
		go func() {
			defer close(done)
			// Send periodic keep-alive messages
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					// Send keep-alive
					fmt.Fprint(w, ": keep-alive\n\n")
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
				case <-r.Context().Done():
					// Context cancelled, stop immediately
					return
				case <-done:
					// Connection closed, stop immediately
					return
				case <-s.ctx.Done():
					// Server shutting down, stop immediately
					return
				}
			}
		}()
		
		// Wait for connection to close or server shutdown
		select {
		case <-r.Context().Done():
		case <-s.ctx.Done():
		}
		return
	}
	
	if r.Method == "POST" {
		// Handle MCP messages sent via POST to SSE endpoint
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		var req types.MCPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		response := s.handleMCPRequest(&req)
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.logger.Error().Err(err).Msg("Failed to encode response")
		}
		return
	}
	
	// Handle other methods
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleMCPRequest processes MCP requests
func (s *Server) handleMCPRequest(req *types.MCPRequest) *types.MCPResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourcesRead(req)
	case "logging/setLevel":
		return s.handleLoggingSetLevel(req)
	default:
		return &types.MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &types.MCPError{
				Code:    -32601,
				Message: "Method not found",
				Data:    fmt.Sprintf("Unknown method: %s", req.Method),
			},
		}
	}
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(req *types.MCPRequest) *types.MCPResponse {
	var initReq types.InitializeRequest
	if err := json.Unmarshal(req.Params, &initReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	// Initialize local tools and resources from config
	s.initializeFromConfig()
	
	// Connect to upstream servers and aggregate their capabilities
	s.connectToUpstreamServers()

	result := types.InitializeResponse{
		ProtocolVersion: s.config.MCP.Version,
		Capabilities: types.ServerCapabilities{
			Tools:     &types.ToolCapability{ListChanged: s.config.MCP.Capabilities.Tools.ListChanged},
			Resources: &types.ResourceCapability{
				Subscribe:   s.config.MCP.Capabilities.Resources.Subscribe,
				ListChanged: s.config.MCP.Capabilities.Resources.ListChanged,
			},
			Logging: &types.LoggingCapability{},
		},
		ServerInfo: types.ServerInfo{
			Name:    s.config.MCP.Name,
			Version: "1.0.0",
		},
	}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsList handles the tools/list request
func (s *Server) handleToolsList(req *types.MCPRequest) *types.MCPResponse {
	s.mu.RLock()
	tools := make([]types.Tool, 0, len(s.tools))
	for _, tool := range s.tools {
		tools = append(tools, *tool)
	}
	s.mu.RUnlock()

	result := types.ToolListResponse{Tools: tools}
	
	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsCall handles the tools/call request
func (s *Server) handleToolsCall(req *types.MCPRequest) *types.MCPResponse {
	var callReq types.CallToolRequest
	if err := json.Unmarshal(req.Params, &callReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	s.mu.RLock()
	toolName := strings.ReplaceAll(callReq.Name, ":", "_")
	tool, exists := s.tools[toolName]

	s.mu.RUnlock()
	
	if !exists {
		s.logger.Warn().
			Str("tool_name", callReq.Name).
			Interface("available_tools", maps.Keys(s.tools)).
			Msg("Tool not found")
		return s.errorResponse(req.ID, -32602, "Tool not found", fmt.Sprintf("Tool '%s' not found", callReq.Name))
	}

	// Check if this is a local tool or needs to be routed to an upstream server
	result := s.routeToolCall(tool, callReq.Name, callReq.Arguments)
	
	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleResourcesList handles the resources/list request
func (s *Server) handleResourcesList(req *types.MCPRequest) *types.MCPResponse {
	resources := make([]types.Resource, 0, len(s.resources))
	for _, resource := range s.resources {
		resources = append(resources, *resource)
	}

	result := types.ResourceListResponse{Resources: resources}
	
	return &types.MCPResponse{
		JSONRPC: "2.0",
	ID:      req.ID,
		Result:  result,
	}
}

// handleResourcesRead handles the resources/read request
func (s *Server) handleResourcesRead(req *types.MCPRequest) *types.MCPResponse {
	var readReq types.ReadResourceRequest
	if err := json.Unmarshal(req.Params, &readReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	s.mu.RLock()
	// Check if resource exists
	resource, exists := s.resources[readReq.URI]
	s.mu.RUnlock()
	
	if !exists {
		return s.errorResponse(req.ID, -32602, "Resource not found", fmt.Sprintf("Resource '%s' not found", readReq.URI))
	}

	// Route the resource read request
	content := s.routeResourceRead(resource, readReq.URI)
	
	result := types.ReadResourceResponse{Contents: []types.ResourceContent{content}}
	
	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleLoggingSetLevel handles the logging/setLevel request
func (s *Server) handleLoggingSetLevel(req *types.MCPRequest) *types.MCPResponse {
	var levelReq types.LoggingSetLevelRequest
	if err := json.Unmarshal(req.Params, &levelReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	// Set logging level (implement actual logging level change)
	s.logger.Info().Str("level", levelReq.Level).Msg("Setting log level")
	logger.SetLogLevel(levelReq.Level)
	
	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{},
	}
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"name":   s.config.MCP.Name,
		"version": s.config.MCP.Version,
	})
}

// handleInfo handles info requests
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	info := map[string]interface{}{
		"name":        s.config.MCP.Name,
		"description": s.config.MCP.Description,
		"version":     s.config.MCP.Version,
		"capabilities": s.config.MCP.Capabilities,
		"tools":       len(s.tools),
		"resources":   len(s.resources),
	}
	json.NewEncoder(w).Encode(info)
}

// handleAdminPanel serves the admin panel HTML
func (s *Server) handleAdminPanel(w http.ResponseWriter, r *http.Request) {
	// Always serve the same HTML file but inject auth configuration
	adminFile := "web/admin.html"

	// Try to read the admin panel HTML file
	content, err := os.ReadFile(adminFile)
	if err != nil {
		s.logger.Error().Err(err).Str("file", adminFile).Msg("Failed to read admin panel file")
		http.Error(w, "Admin panel not available", http.StatusInternalServerError)
		return
	}

	// Inject auth configuration into the HTML
	contentStr := string(content)
	authConfig := fmt.Sprintf(`<script>window.AUTH_ENABLED = %t;</script>`, s.config.Security.EnableAuth)
	
	// Insert the auth configuration script before the closing </head> tag
	contentStr = strings.Replace(contentStr, "</head>", authConfig+"\n</head>", 1)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(contentStr))
}

// initializeFromConfig initializes tools and resources from configuration
func (s *Server) initializeFromConfig() {
	// Initialize tools
	for _, toolConfig := range s.config.MCP.Tools {
		tool := &types.Tool{
			Name:        toolConfig.Name,
			Description: toolConfig.Description,
			InputSchema: toolConfig.InputSchema,
		}
		s.tools[tool.Name] = tool
	}

	// Initialize resources
	for _, resourceConfig := range s.config.MCP.Resources {
		resource := &types.Resource{
			URI:         resourceConfig.URI,
			Name:        resourceConfig.Name,
			Description: resourceConfig.Description,
			MimeType:    resourceConfig.MimeType,
		}
		s.resources[resource.URI] = resource
	}
}

// executeTool executes a tool by routing it to the appropriate upstream server
func (s *Server) executeTool(tool *types.Tool, arguments map[string]interface{}) types.CallToolResponse {
	// Route all tool calls to upstream servers
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find which upstream server has this tool
	for clientName, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			clientTools := mcpClient.GetTools()
			if _, exists := clientTools[tool.Name]; exists {
				// Route to upstream server
				if result, err := mcpClient.CallTool(tool.Name, arguments); err == nil {
					return *result
				} else {
					s.logger.Error().
						Err(err).
						Str("tool_name", tool.Name).
						Str("upstream", clientName).
						Msg("Error calling tool on upstream")
					return types.CallToolResponse{
						Content: []types.Content{{Type: "text", Text: fmt.Sprintf("Error calling upstream tool: %v", err)}},
						IsError: true,
					}
				}
			}
		}
	}

	// If tool not found in any upstream server, return error
	return types.CallToolResponse{
		Content: []types.Content{{Type: "text", Text: fmt.Sprintf("Tool '%s' not found in any upstream server", tool.Name)}},
		IsError: true,
	}
}

// readResource reads a resource and returns its content
func (s *Server) readResource(resource *types.Resource) types.ResourceContent {
	// This is a placeholder implementation
	// In a real implementation, you would read from actual resources
	
	return types.ResourceContent{
		URI:      resource.URI,
		MimeType: resource.MimeType,
		Text:     fmt.Sprintf("Content of resource: %s", resource.Name),
	}
}

// errorResponse creates an error response
func (s *Server) errorResponse(id interface{}, code int, message, data string) *types.MCPResponse {
	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &types.MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// connectToUpstreamServers connects to all enabled upstream servers from database
func (s *Server) connectToUpstreamServers() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get enabled servers from database
	servers, err := s.db.ListUpstreamServersForConnection(true) // only enabled servers with auth data
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to load upstream servers from database")
		return
	}

	for _, serverRecord := range servers {
		upstream := serverRecord.ToUpstreamServer()
		
		// Set status to "starting" for stdio servers since they take time to initialize
		if upstream.Type == "stdio" {
			s.db.UpdateUpstreamServerStatus(serverRecord.ID, "starting")
		}
		
		mcpClient := client.NewMCPClient(upstream)
		
		if err := mcpClient.Connect(); err != nil {
			s.logger.Error().
				Err(err).
				Str("upstream", upstream.Name).
				Msg("Failed to connect to upstream server")
			// Update status in database
			s.db.UpdateUpstreamServerStatus(serverRecord.ID, "error")
			continue
		}

		s.clients[upstream.Name] = mcpClient
		s.clientsByID[serverRecord.ID] = mcpClient
		
		// Update status in database
		s.db.UpdateUpstreamServerStatus(serverRecord.ID, "connected")
		
		// Aggregate tools from this upstream server
		for name, tool := range mcpClient.GetTools() {
			s.tools[name] = tool
		}
		
		// Aggregate resources from this upstream server
		for uri, resource := range mcpClient.GetResources() {
			s.resources[uri] = resource
		}
		
		// Aggregate prompts from this upstream server (but don't expose them in gateway API)
		for name, prompt := range mcpClient.GetPrompts() {
			s.prompts[name] = prompt
		}

		s.logger.Info().Str("upstream", upstream.Name).Msg("Successfully connected to upstream server")
	}

	// Update stats
	s.updateStats()
}

// ConnectUpstreamServer connects to a single upstream server by ID
func (s *Server) ConnectUpstreamServer(serverID int64) error {
	// Get the server record from database
	serverRecord, err := s.db.GetUpstreamServer(serverID)
	if err != nil {
		return fmt.Errorf("failed to get upstream server: %w", err)
	}

	// Skip if server is not enabled
	if !serverRecord.Enabled {
		return fmt.Errorf("server is not enabled")
	}

	upstream := serverRecord.ToUpstreamServer()
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Set status to "starting" for stdio servers since they take time to initialize
	s.logger.Info().Str("upstream", upstream.Name).Str("type", upstream.Type).Msg("Connecting to upstream server")
	if upstream.Type == "stdio" {
		s.db.UpdateUpstreamServerStatus(serverRecord.ID, "starting")
	}
	
	mcpClient := client.NewMCPClient(upstream)
	
	if err := mcpClient.Connect(); err != nil {
		s.logger.Error().
			Err(err).
			Str("upstream", upstream.Name).
			Msg("Failed to connect to upstream server")
		// Update status in database
		s.db.UpdateUpstreamServerStatus(serverRecord.ID, "error")
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Close existing connection if it exists
	if existingClient, exists := s.clients[upstream.Name]; exists {
		existingClient.Close()
	}
	if existingClient, exists := s.clientsByID[serverRecord.ID]; exists {
		existingClient.Close()
	}

	s.clients[upstream.Name] = mcpClient
	s.clientsByID[serverRecord.ID] = mcpClient
	
	// Update status in database
	s.db.UpdateUpstreamServerStatus(serverRecord.ID, "connected")
	
	// Aggregate tools from this upstream server
	for name, tool := range mcpClient.GetTools() {
		s.tools[name] = tool
	}
	
	// Aggregate resources from this upstream server
	for uri, resource := range mcpClient.GetResources() {
		s.resources[uri] = resource
	}
	
	// Aggregate prompts from this upstream server (but don't expose them in gateway API)
	for name, prompt := range mcpClient.GetPrompts() {
		s.prompts[name] = prompt
	}

	s.logger.Info().Str("upstream", upstream.Name).Msg("Successfully connected to upstream server")
	
	// Update stats
	s.updateStats()
	
	return nil
}

// handleRefreshConnections handles connection refresh requests
func (s *Server) handleRefreshConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.logger.Info().Msg("Refreshing upstream server connections...")
	
	// Close existing connections
	s.mu.Lock()
	for name, mcpClient := range s.clients {
		if err := mcpClient.Close(); err != nil {
			s.logger.Error().
				Err(err).
				Str("upstream", name).
				Msg("Error closing connection to upstream")
		}
	}
	
	// Clear existing clients and aggregated data
	s.clients = make(map[string]*client.MCPClient)
	s.clientsByID = make(map[int64]*client.MCPClient)
	s.tools = make(map[string]*types.Tool)
	s.resources = make(map[string]*types.Resource)
	s.prompts = make(map[string]*types.Prompt)
	s.mu.Unlock()
	
	// Re-initialize local tools/resources
	s.initializeFromConfig()
	
	// Reconnect to upstream servers
	s.connectToUpstreamServers()
	
	response := map[string]interface{}{
		"success": true,
		"message": "Connections refreshed successfully",
		"stats":   s.stats,
	}
	
	json.NewEncoder(w).Encode(response)
}

// DisconnectUpstreamServer disconnects and removes a specific upstream server connection
func (s *Server) DisconnectUpstreamServer(serverID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Find the client by ID
	client, exists := s.clientsByID[serverID]
	if !exists {
		// Server not connected, nothing to do
		return nil
	}
	
	// Close the connection
	if err := client.Close(); err != nil {
		// Don't log normal process exit codes as errors
		if err.Error() != "exit status 1" && err.Error() != "exit status 0" {
			s.logger.Error().
				Err(err).
				Int64("server_id", serverID).
				Msg("Error closing connection to upstream server")
		} else {
			s.logger.Debug().
				Err(err).
				Int64("server_id", serverID).
				Msg("Upstream server process exited")
		}
	}
	
	// Remove from both maps
	// First find the server name to remove from clients map
	for name, c := range s.clients {
		if c == client {
			delete(s.clients, name)
			break
		}
	}
	delete(s.clientsByID, serverID)
	
	// Remove tools, resources, and prompts from this server
	// Note: This is a simple approach that removes all and re-aggregates from remaining servers
	// In a more sophisticated implementation, we would track which server contributed which items
	s.tools = make(map[string]*types.Tool)
	s.resources = make(map[string]*types.Resource)
	s.prompts = make(map[string]*types.Prompt)
	
	// Re-initialize local tools/resources
	s.initializeFromConfig()
	
	// Re-aggregate from remaining connected servers
	for _, remainingClient := range s.clients {
		// Aggregate tools
		for name, tool := range remainingClient.GetTools() {
			s.tools[name] = tool
		}
		
		// Aggregate resources
		for uri, resource := range remainingClient.GetResources() {
			s.resources[uri] = resource
		}
		
		// Aggregate prompts
		for name, prompt := range remainingClient.GetPrompts() {
			s.prompts[name] = prompt
		}
	}
	
	// Update stats
	s.updateStats()
	
	s.logger.Info().Int64("server_id", serverID).Msg("Disconnected upstream server")
	return nil
}

// routeToolCall routes a tool call to the appropriate upstream server or executes locally
func (s *Server) routeToolCall(tool *types.Tool, name string, arguments map[string]interface{}) types.CallToolResponse {
	// Determine which upstream server this tool belongs to
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if this is a prefixed tool (from upstream server)
	for clientName, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			clientTools := mcpClient.GetTools()
			if _, exists := clientTools[name]; exists {
				// Route to upstream server
				if result, err := mcpClient.CallTool(name, arguments); err == nil {
					s.stats.RequestsProcessed++
					return *result
				} else {
					s.logger.Error().
						Err(err).
						Str("tool_name", name).
						Str("upstream", clientName).
						Msg("Error calling tool on upstream")
					return types.CallToolResponse{
						Content: []types.Content{{Type: "text", Text: fmt.Sprintf("Error calling upstream tool: %v", err)}},
						IsError: true,
					}
				}
			}
		}
	}

	// Execute locally if not found in upstream servers
	s.stats.RequestsProcessed++
	return s.executeTool(tool, arguments)
}

// routeResourceRead routes a resource read to the appropriate upstream server or reads locally
func (s *Server) routeResourceRead(resource *types.Resource, uri string) types.ResourceContent {
	// Determine which upstream server this resource belongs to
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if this is a prefixed resource (from upstream server)
for clientName, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			clientResources := mcpClient.GetResources()
			if _, exists := clientResources[uri]; exists {
				// Route to upstream server
				if result, err := mcpClient.ReadResource(uri); err == nil {
					if len(result.Contents) > 0 {
						return result.Contents[0]
					}
				} else {
					s.logger.Error().
						Err(err).
						Str("resource_uri", uri).
						Str("upstream", clientName).
						Msg("Error reading resource on upstream")
				}
			}
		}
	}

	// Read locally if not found in upstream servers
	return s.readResource(resource)
}

// updateStats updates the gateway statistics
func (s *Server) updateStats() {
	connectedServers := 0
	for _, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			connectedServers++
		}
	}

	// Get total server count from database
	servers, err := s.db.ListUpstreamServers(false)
	totalServers := 0
	if err == nil {
		totalServers = len(servers)
	}

	s.stats = types.GatewayStats{
		UpstreamServers:   totalServers,
		ConnectedServers:  connectedServers,
		TotalTools:        len(s.tools),
		TotalResources:    len(s.resources),
		RequestsProcessed: s.stats.RequestsProcessed, // Keep the existing count
	}
}

// handleGatewayStatus handles gateway status requests
func (s *Server) handleGatewayStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.mu.RLock()
	status := make(map[string]interface{})
	upstreams := make([]map[string]interface{}, 0)
	
	for name, mcpClient := range s.clients {
		tools := mcpClient.GetTools()
		toolDetails := make([]map[string]interface{}, 0, len(tools))
		for toolName, tool := range tools {
			toolDetails = append(toolDetails, map[string]interface{}{
				"name":        toolName,
				"description": tool.Description,
			})
		}
		
		upstream := map[string]interface{}{
			"name":         name,
			"connected":    mcpClient.IsConnected(),
			"tools":        len(tools),
			"tool_details": toolDetails,
			"resources":    len(mcpClient.GetResources()),
			"prompts":      len(mcpClient.GetPrompts()),
		}
		upstreams = append(upstreams, upstream)
	}
	s.mu.RUnlock()

	status["gateway"] = map[string]interface{}{
		"name":             s.config.MCP.Name,
		"version":          "1.0.0",
		"upstream_servers": upstreams,
		"total_tools":      len(s.tools),
		"total_resources":  len(s.resources),
	}

	json.NewEncoder(w).Encode(status)
}

// handleUpstreamServers handles upstream servers list requests
func (s *Server) handleUpstreamServers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	servers, err := s.db.ListUpstreamServers(false)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load upstream servers: %v", err), http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(servers)
}

// handleGatewayStats handles gateway statistics requests
func (s *Server) handleGatewayStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.mu.RLock()
	s.updateStats()
	stats := s.stats
	s.mu.RUnlock()
	
	json.NewEncoder(w).Encode(stats)
}

// Start starts the gateway server (optional method for initialization)
func (s *Server) Start() error {
	s.logger.Info().Msg("Starting MCP Gateway Server...")
	
	// Connect to upstream servers at startup
	s.connectToUpstreamServers()
	
	s.logger.Info().Int("upstream_count", len(s.clients)).Msg("MCP Gateway Server started")
	return nil
}