package local

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nadav-yo/mcp-gateway/internal/client"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
	"github.com/rs/zerolog"
)

// MCPServer represents a local MCP server that can connect to a gateway
type MCPServer struct {
	config      *config.Config
	mcpConfig   *MCPConfig
	initialized bool
	mu          sync.RWMutex

	// Local capabilities (aggregated from upstream servers)
	tools     map[string]*types.Tool
	resources map[string]*types.Resource

	// Upstream MCP servers from mcp.json
	clients map[string]*client.MCPClient

	// Gateway connection
	gatewayClient *client.MCPClient

	// Curation data
	curatedServers []CuratedServer

	// Server state
	logger    zerolog.Logger
	mcpLogger *MCPLogger
	ctx       context.Context
	startTime time.Time

	// Notification channel for sending notifications to VS Code
	notificationChan chan *types.MCPNotification
}

// CuratedServer represents a server from the gateway's curated list
type CuratedServer struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
	URL         string   `json:"url,omitempty"`
	Description string   `json:"description,omitempty"`
}

// NewMCPServer creates a new local MCP server instance
func NewMCPServer(cfg *config.Config, gatewayURL string) (*MCPServer, error) {
	return NewMCPServerWithConfig(cfg, gatewayURL, "mcp.json")
}

// NewMCPServerWithConfig creates a new local MCP server instance with custom mcp.json path
func NewMCPServerWithConfig(cfg *config.Config, gatewayURL, mcpConfigPath string) (*MCPServer, error) {
	mcpCfg, err := LoadMCPConfig(mcpConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load mcp.json: %w", err)
	}
	if err := mcpCfg.Validate(); err != nil {
		return nil, fmt.Errorf("mcp.json validation failed: %w", err)
	}
	return &MCPServer{
		config:           cfg,
		mcpConfig:        mcpCfg,
		tools:            make(map[string]*types.Tool),
		resources:        make(map[string]*types.Resource),
		clients:          make(map[string]*client.MCPClient),
		logger:           logger.GetLogger("mcp-local"),
		startTime:        time.Now(),
		notificationChan: make(chan *types.MCPNotification, 100),
	}, nil
}

// SetMCPLogger sets the MCP-compliant logger for the server
func (s *MCPServer) SetMCPLogger(logger *MCPLogger) {
	s.mcpLogger = logger
}

// Start initializes the MCP server and optionally connects to the gateway
func (s *MCPServer) Start(ctx context.Context) error {
	s.ctx = ctx

	// Connect to gateway first if URL is provided to get curated servers
	if s.mcpConfig.CurationRegistry.URL != "" {
		if err := s.connectToGateway(); err != nil {
			if s.mcpLogger != nil {
				s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Failed to connect to gateway: %v", err))
			}
		} else {
			// Fetch curated servers from gateway
			if err := s.fetchCuratedServers(); err != nil {
				if s.mcpLogger != nil {
					s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Failed to fetch curated servers: %v", err))
				}
			}
		}
	}

	// Start upstream connections asynchronously so we don't block VS Code
	go func() {
		// Add a small delay to ensure the initialize response is sent first
		time.Sleep(100 * time.Millisecond)

		if err := s.connectToUpstreamServers(); err != nil {
			if s.mcpLogger != nil {
				s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Failed to connect to some upstream servers: %v", err))
			}
		}

		if s.mcpLogger != nil {
			s.mcpLogger.Info("mcp-local", fmt.Sprintf("Upstream connections complete - servers: %d, tools: %d, resources: %d",
				len(s.clients), len(s.tools), len(s.resources)))
		}
	}()

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", "Local MCP Server ready to handle requests")
	}

	return nil
}

// HandleRequest processes an MCP request and returns a response
func (s *MCPServer) HandleRequest(req *types.MCPRequest) *types.MCPResponse {
	if s.mcpLogger != nil {
		s.mcpLogger.Debug("mcp-local", fmt.Sprintf("Handling MCP request: %s (id: %v)", req.Method, req.ID))
	}

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
		return s.errorResponse(req.ID, -32601, "Method not found", fmt.Sprintf("Unknown method: %s", req.Method))
	}
}

// handleInitialize handles the initialize request
func (s *MCPServer) handleInitialize(req *types.MCPRequest) *types.MCPResponse {
	s.mu.Lock()
	s.initialized = true
	s.mu.Unlock()

	result := types.InitializeResponse{
		ProtocolVersion: s.config.MCP.Version,
		Capabilities: types.ServerCapabilities{
			Tools: &types.ToolCapability{
				ListChanged: s.config.MCP.Capabilities.Tools.ListChanged,
			},
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

	response := &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", "MCP Server initialized - responding immediately")
	}

	return response
}

// handleToolsList handles the tools/list request
func (s *MCPServer) handleToolsList(req *types.MCPRequest) *types.MCPResponse {
	s.mu.RLock()
	tools := make([]types.Tool, 0, len(s.tools))
	for _, tool := range s.tools {
		tools = append(tools, *tool)
	}
	s.mu.RUnlock()

	if s.mcpLogger != nil && len(tools) == 0 {
		s.mcpLogger.Debug("mcp-local", "No tools available yet - upstream servers may still be connecting")
	}

	result := types.ToolListResponse{Tools: tools}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsCall handles the tools/call request
func (s *MCPServer) handleToolsCall(req *types.MCPRequest) *types.MCPResponse {
	var callReq types.CallToolRequest
	if err := json.Unmarshal(req.Params, &callReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	s.mu.RLock()
	tool, exists := s.tools[callReq.Name]
	s.mu.RUnlock()

	if !exists {
		return s.errorResponse(req.ID, -32602, "Tool not found", fmt.Sprintf("Tool '%s' not found", callReq.Name))
	}

	// Route the tool call to the appropriate upstream server
	result := s.routeToolCall(tool, callReq.Name, callReq.Arguments)

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleResourcesList handles the resources/list request
func (s *MCPServer) handleResourcesList(req *types.MCPRequest) *types.MCPResponse {
	s.mu.RLock()
	resources := make([]types.Resource, 0, len(s.resources))
	for _, resource := range s.resources {
		resources = append(resources, *resource)
	}
	s.mu.RUnlock()

	if s.mcpLogger != nil && len(resources) == 0 {
		s.mcpLogger.Debug("mcp-local", "No resources available yet - upstream servers may still be connecting")
	}

	result := types.ResourceListResponse{Resources: resources}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleResourcesRead handles the resources/read request
func (s *MCPServer) handleResourcesRead(req *types.MCPRequest) *types.MCPResponse {
	var readReq types.ReadResourceRequest
	if err := json.Unmarshal(req.Params, &readReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	s.mu.RLock()
	resource, exists := s.resources[readReq.URI]
	s.mu.RUnlock()

	if !exists {
		return s.errorResponse(req.ID, -32602, "Resource not found", fmt.Sprintf("Resource '%s' not found", readReq.URI))
	}

	// Route the resource read to the appropriate upstream server
	content := s.routeResourceRead(resource, readReq.URI)

	result := types.ReadResourceResponse{
		Contents: []types.ResourceContent{content},
	}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleLoggingSetLevel handles the logging/setLevel request
func (s *MCPServer) handleLoggingSetLevel(req *types.MCPRequest) *types.MCPResponse {
	var levelReq types.LoggingSetLevelRequest
	if err := json.Unmarshal(req.Params, &levelReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	// Set logging level for MCP logger
	if s.mcpLogger != nil {
		s.mcpLogger.SetLevel(levelReq.Level)
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Setting log level to: %s", levelReq.Level))
	}

	result := map[string]interface{}{}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// connectToUpstreamServers connects to all enabled upstream servers from mcp.json
func (s *MCPServer) connectToUpstreamServers() error {
	// Get enabled servers
	enabledServers := s.mcpConfig.GetEnabledServers()
	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Loading upstream servers from mcp.json: %d servers", len(enabledServers)))
	}

	for name, upstream := range enabledServers {
		if s.mcpLogger != nil {
			s.mcpLogger.Info("mcp-local", fmt.Sprintf("Connecting to upstream server: %s (type: %s)", name, upstream.Type))
		}

		// Check if server is in curated list (if curation is enabled)
		if s.mcpConfig.CurationRegistry.URL != "" && s.mcpConfig.CurationRegistry.Token != "" {
			if !s.isServerCurated(upstream) {
				if s.mcpLogger != nil {
					s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Server %s is not in curated list, skipping connection", name))
				}
				continue
			} else {
				if s.mcpLogger != nil {
					s.mcpLogger.Info("mcp-local", fmt.Sprintf("Server %s validated against curated list", name))
				}
			}
		} else {
			if s.mcpLogger != nil {
				s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Curation not enabled, connecting to server %s without validation", name))
			}
		}

		// Connect to upstream server with timeout protection
		mcpClient := client.NewQuietMCPClient(upstream)

		// Use a timeout context for connection
		connectCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)

		connectErr := make(chan error, 1)
		go func() {
			connectErr <- mcpClient.Connect()
		}()

		select {
		case err := <-connectErr:
			cancel()
			if err != nil {
				if s.mcpLogger != nil {
					s.mcpLogger.Error("mcp-local", fmt.Sprintf("Failed to connect to upstream server %s: %v", name, err))
				}
				continue
			}
		case <-connectCtx.Done():
			cancel()
			if s.mcpLogger != nil {
				s.mcpLogger.Error("mcp-local", fmt.Sprintf("Timeout connecting to upstream server %s", name))
			}
			continue
		}

		s.clients[name] = mcpClient

		// Track if we added any new tools or resources
		toolsAdded := 0
		resourcesAdded := 0

		// Aggregate tools from this upstream server
		for toolName, tool := range mcpClient.GetTools() {
			s.tools[toolName] = tool
			toolsAdded++
		}

		// Aggregate resources from this upstream server
		for uri, resource := range mcpClient.GetResources() {
			s.resources[uri] = resource
			resourcesAdded++
		}

		if s.mcpLogger != nil {
			s.mcpLogger.Info("mcp-local", fmt.Sprintf("Successfully connected to upstream server %s - tools: %d, resources: %d",
				name, len(mcpClient.GetTools()), len(mcpClient.GetResources())))
		}

		// Send notifications if we added tools or resources
		if toolsAdded > 0 {
			s.notifyToolsChanged()
		}
		if resourcesAdded > 0 {
			s.notifyResourcesChanged()
		}
	}

	return nil
}

// routeToolCall routes a tool call to the appropriate upstream server
func (s *MCPServer) routeToolCall(tool *types.Tool, name string, arguments map[string]interface{}) types.CallToolResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find which upstream server has this tool
	for clientName, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			clientTools := mcpClient.GetTools()
			if _, exists := clientTools[name]; exists {
				// Route to upstream server
				if result, err := mcpClient.CallTool(name, arguments); err == nil {
					if s.mcpLogger != nil {
						s.mcpLogger.Debug("mcp-local", fmt.Sprintf("Tool executed successfully: %s (upstream: %s)", name, clientName))
					}
					return *result
				} else {
					if s.mcpLogger != nil {
						s.mcpLogger.Error("mcp-local", fmt.Sprintf("Error calling tool %s on upstream %s: %v", name, clientName, err))
					}
					return types.CallToolResponse{
						Content: []types.Content{{Type: "text", Text: fmt.Sprintf("Error calling upstream tool: %v", err)}},
						IsError: true,
					}
				}
			}
		}
	}

	// Tool not found in any upstream server
	return types.CallToolResponse{
		Content: []types.Content{{Type: "text", Text: fmt.Sprintf("Tool '%s' not found in any upstream server", name)}},
		IsError: true,
	}
}

// routeResourceRead routes a resource read to the appropriate upstream server
func (s *MCPServer) routeResourceRead(resource *types.Resource, uri string) types.ResourceContent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find which upstream server has this resource
	for clientName, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			clientResources := mcpClient.GetResources()
			if _, exists := clientResources[uri]; exists {
				// Route to upstream server
				if result, err := mcpClient.ReadResource(uri); err == nil {
					if s.mcpLogger != nil {
						s.mcpLogger.Debug("mcp-local", fmt.Sprintf("Resource read successfully: %s (upstream: %s)", uri, clientName))
					}
					if len(result.Contents) > 0 {
						return result.Contents[0]
					}
				} else {
					if s.mcpLogger != nil {
						s.mcpLogger.Error("mcp-local", fmt.Sprintf("Error reading resource %s from upstream %s: %v", uri, clientName, err))
					}
				}
			}
		}
	}

	// Resource not found in any upstream server
	return types.ResourceContent{
		URI:      uri,
		MimeType: "text/plain",
		Text:     fmt.Sprintf("Resource '%s' not found in any upstream server", uri),
	}
}

// connectToGateway establishes a connection to the MCP gateway
func (s *MCPServer) connectToGateway() error {
	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Connecting to MCP Gateway: %s", s.mcpConfig.CurationRegistry.URL))
	}

	// Create upstream server config for the gateway
	upstream := &types.UpstreamServer{
		Name:    "gateway",
		URL:     s.mcpConfig.CurationRegistry.URL,
		Type:    "http",
		Enabled: true,
		Timeout: "30s",
		Headers: map[string]string{
			"Authorization": "Bearer " + s.mcpConfig.CurationRegistry.Token,
		},
	}

	// Create gateway client
	s.gatewayClient = client.NewQuietMCPClient(upstream)

	// Connect to gateway
	if err := s.gatewayClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to gateway: %w", err)
	}

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", "Successfully connected to MCP Gateway")
	}
	return nil
}

// fetchCuratedServers retrieves the curated servers list from the gateway
func (s *MCPServer) fetchCuratedServers() error {
	if s.mcpConfig.CurationRegistry.URL == "" {
		return fmt.Errorf("gateway URL not configured")
	}

	if s.mcpConfig.CurationRegistry.Token == "" {
		if s.mcpLogger != nil {
			s.mcpLogger.Warning("mcp-local", "No curation token provided (MCP_CURATION_TOKEN env var), skipping curation validation")
		}
		return nil
	}

	// Construct curation endpoint URL
	curationURL := s.mcpConfig.CurationRegistry.URL + "/gateway/curated-servers"

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Fetching curated servers from: %s", curationURL))
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", curationURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+s.mcpConfig.CurationRegistry.Token)
	req.Header.Set("User-Agent", "mcp-local/1.0")

	// Make the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch curated servers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned status %d", resp.StatusCode)
	}

	// Parse the response
	var curationResponse struct {
		Servers []CuratedServer `json:"servers"`
		Total   int             `json:"total"`
		Version string          `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&curationResponse); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	s.mu.Lock()
	s.curatedServers = curationResponse.Servers
	s.mu.Unlock()

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Successfully fetched %d curated servers from gateway", len(curationResponse.Servers)))
	}

	return nil
}

// isServerCurated checks if a server configuration matches the curated list
func (s *MCPServer) isServerCurated(serverConfig *types.UpstreamServer) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If no curated servers loaded, allow all (fallback behavior)
	if len(s.curatedServers) == 0 {
		return true
	}

	// Check if this server matches any curated server
	for _, curated := range s.curatedServers {
		if serverConfig.Type == "stdio" && curated.Type == "stdio" {
			if strings.HasPrefix(strings.Join(serverConfig.Command, " "), curated.Command) {
				return true
			}
		} else if (serverConfig.Type == "http" || serverConfig.Type == "websocket") &&
			(curated.Type == "http" || curated.Type == "websocket") {
			if serverConfig.URL == curated.URL {
				return true
			}
		}
	}
	return false
}

// argsMatchPrefix checks if server args match curated args prefix
func (s *MCPServer) argsMatchPrefix(serverArgs, curatedArgs []string) bool {
	if len(serverArgs) < len(curatedArgs) {
		return false
	}

	for i, curatedArg := range curatedArgs {
		if i >= len(serverArgs) || serverArgs[i] != curatedArg {
			return false
		}
	}

	return true
}

// errorResponse creates an error response
func (s *MCPServer) errorResponse(id interface{}, code int, message, data string) *types.MCPResponse {
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

// GetNotifications returns a channel to receive notifications
func (s *MCPServer) GetNotifications() <-chan *types.MCPNotification {
	return s.notificationChan
}

// sendNotification sends a notification to the client
func (s *MCPServer) sendNotification(method string, params interface{}) {
	notification := &types.MCPNotification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}

	select {
	case s.notificationChan <- notification:
		if s.mcpLogger != nil {
			s.mcpLogger.Debug("mcp-local", fmt.Sprintf("Sent notification: %s", method))
		}
	default:
		if s.mcpLogger != nil {
			s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Notification channel full, dropping notification: %s", method))
		}
	}
}

// notifyToolsChanged sends a tools/list_changed notification
func (s *MCPServer) notifyToolsChanged() {
	s.sendNotification("notifications/tools/list_changed", map[string]interface{}{})
}

// notifyResourcesChanged sends a resources/list_changed notification
func (s *MCPServer) notifyResourcesChanged() {
	s.sendNotification("notifications/resources/list_changed", map[string]interface{}{})
}
