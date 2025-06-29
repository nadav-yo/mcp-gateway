package local

import (
	"context"
	"encoding/json"
	"fmt"
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
	config        *config.Config
	gatewayURL    string
	mcpConfigPath string
	initialized   bool
	mu            sync.RWMutex

	// Local capabilities (aggregated from upstream servers)
	tools     map[string]*types.Tool
	resources map[string]*types.Resource

	// Upstream MCP servers from mcp.json
	clients map[string]*client.MCPClient

	// Gateway connection
	gatewayClient *client.MCPClient

	// Server state
	logger    zerolog.Logger
	mcpLogger *MCPLogger
	ctx       context.Context
	startTime time.Time
}

// NewMCPServer creates a new local MCP server instance
func NewMCPServer(cfg *config.Config, gatewayURL string) (*MCPServer, error) {
	return NewMCPServerWithConfig(cfg, gatewayURL, "mcp.json")
}

// NewMCPServerWithConfig creates a new local MCP server instance with custom mcp.json path
func NewMCPServerWithConfig(cfg *config.Config, gatewayURL, mcpConfigPath string) (*MCPServer, error) {
	server := &MCPServer{
		config:        cfg,
		gatewayURL:    gatewayURL,
		mcpConfigPath: mcpConfigPath,
		tools:         make(map[string]*types.Tool),
		resources:     make(map[string]*types.Resource),
		clients:       make(map[string]*client.MCPClient),
		logger:        logger.GetLogger("mcp-local"),
		startTime:     time.Now(),
	}

	return server, nil
}

// SetMCPLogger sets the MCP-compliant logger for the server
func (s *MCPServer) SetMCPLogger(logger *MCPLogger) {
	s.mcpLogger = logger
}

// Start initializes the MCP server and optionally connects to the gateway
func (s *MCPServer) Start(ctx context.Context) error {
	s.ctx = ctx

	// Load and connect to upstream servers from mcp.json
	if err := s.connectToUpstreamServers(); err != nil {
		if s.mcpLogger != nil {
			s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Failed to connect to some upstream servers: %v", err))
		}
	}

	// Connect to gateway if URL is provided
	if s.gatewayURL != "" {
		if err := s.connectToGateway(); err != nil {
			if s.mcpLogger != nil {
				s.mcpLogger.Warning("mcp-local", fmt.Sprintf("Failed to connect to gateway: %v", err))
			}
		}
	}

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Local MCP Server initialized - upstream_servers: %d, aggregated_tools: %d, aggregated_resources: %d", 
			len(s.clients), len(s.tools), len(s.resources)))
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

	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", "MCP Server initialized")
	}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handleToolsList handles the tools/list request
func (s *MCPServer) handleToolsList(req *types.MCPRequest) *types.MCPResponse {
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
	// Load mcp.json configuration
	mcpConfig, err := LoadMCPConfig(s.mcpConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load mcp.json: %w", err)
	}

	// Validate the configuration
	if err := mcpConfig.Validate(); err != nil {
		if s.mcpLogger != nil {
			s.mcpLogger.Error("mcp-local", fmt.Sprintf("mcp.json validation failed: %v", err))
		}
		return fmt.Errorf("mcp.json validation failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Get enabled servers
	enabledServers := mcpConfig.GetEnabledServers()
	if s.mcpLogger != nil {
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Loading upstream servers from mcp.json: %d servers", len(enabledServers)))
	}

	for name, upstream := range enabledServers {
		if s.mcpLogger != nil {
			s.mcpLogger.Info("mcp-local", fmt.Sprintf("Connecting to upstream server: %s (type: %s)", name, upstream.Type))
		}

		mcpClient := client.NewQuietMCPClient(upstream)

		if err := mcpClient.Connect(); err != nil {
			if s.mcpLogger != nil {
				s.mcpLogger.Error("mcp-local", fmt.Sprintf("Failed to connect to upstream server %s: %v", name, err))
			}
			continue
		}

		s.clients[name] = mcpClient

		// Aggregate tools from this upstream server
		for toolName, tool := range mcpClient.GetTools() {
			s.tools[toolName] = tool
		}

		// Aggregate resources from this upstream server
		for uri, resource := range mcpClient.GetResources() {
			s.resources[uri] = resource
		}

		if s.mcpLogger != nil {
			s.mcpLogger.Info("mcp-local", fmt.Sprintf("Successfully connected to upstream server %s - tools: %d, resources: %d", 
				name, len(mcpClient.GetTools()), len(mcpClient.GetResources())))
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
		s.mcpLogger.Info("mcp-local", fmt.Sprintf("Connecting to MCP Gateway: %s", s.gatewayURL))
	}

	// Create upstream server config for the gateway
	upstream := &types.UpstreamServer{
		Name:    "gateway",
		URL:     s.gatewayURL,
		Type:    "http", // Assume HTTP for now, could be WebSocket
		Enabled: true,
		Timeout: "30s",
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
