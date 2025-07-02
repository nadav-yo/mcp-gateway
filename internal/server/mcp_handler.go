package server

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

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
	case "prompts/list":
		return s.handlePromptsList(req)
	case "prompts/get":
		return s.handlePromptsGet(req)
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
			Tools: &types.ToolCapability{ListChanged: s.config.MCP.Capabilities.Tools.ListChanged},
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
	allTools := make([]types.Tool, 0, len(s.tools))
	for _, tool := range s.tools {
		allTools = append(allTools, *tool)
	}
	s.mu.RUnlock()

	// Filter out blocked tools
	filteredTools := make([]types.Tool, 0, len(allTools))
	for _, tool := range allTools {
		if !s.isToolBlocked(tool.Name) {
			filteredTools = append(filteredTools, tool)
		}
	}

	result := types.ToolListResponse{Tools: filteredTools}

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

	// Check if the tool is blocked
	if s.isToolBlocked(callReq.Name) {
		s.logger.Warn().
			Str("tool_name", callReq.Name).
			Msg("Tool call blocked")
		return s.errorResponse(req.ID, -32603, "Tool blocked", fmt.Sprintf("Tool '%s' is blocked by administrator", callReq.Name))
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
	s.mu.RLock()
	allResources := make([]types.Resource, 0, len(s.resources))
	for _, resource := range s.resources {
		allResources = append(allResources, *resource)
	}
	s.mu.RUnlock()

	// Filter out blocked resources
	filteredResources := make([]types.Resource, 0, len(allResources))
	for _, resource := range allResources {
		if !s.isResourceBlocked(resource.URI) {
			filteredResources = append(filteredResources, resource)
		}
	}

	result := types.ResourceListResponse{Resources: filteredResources}

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

	// Check if the resource is blocked
	if s.isResourceBlocked(readReq.URI) {
		s.logger.Warn().
			Str("resource_uri", readReq.URI).
			Msg("Resource read blocked")
		return s.errorResponse(req.ID, -32603, "Resource blocked", fmt.Sprintf("Resource '%s' is blocked by administrator", readReq.URI))
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

// handlePromptsList handles the prompts/list request
func (s *Server) handlePromptsList(req *types.MCPRequest) *types.MCPResponse {
	s.mu.RLock()
	allPrompts := make([]types.Prompt, 0, len(s.prompts))
	for _, prompt := range s.prompts {
		allPrompts = append(allPrompts, *prompt)
	}
	s.mu.RUnlock()

	// Filter out blocked prompts
	filteredPrompts := make([]types.Prompt, 0, len(allPrompts))
	for _, prompt := range allPrompts {
		if !s.isPromptBlocked(prompt.Name) {
			filteredPrompts = append(filteredPrompts, prompt)
		}
	}

	result := types.PromptListResponse{Prompts: filteredPrompts}

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// handlePromptsGet handles the prompts/get request
func (s *Server) handlePromptsGet(req *types.MCPRequest) *types.MCPResponse {
	var getReq types.GetPromptRequest
	if err := json.Unmarshal(req.Params, &getReq); err != nil {
		return s.errorResponse(req.ID, -32602, "Invalid params", err.Error())
	}

	s.mu.RLock()
	prompt, exists := s.prompts[getReq.Name]
	s.mu.RUnlock()

	if !exists {
		return s.errorResponse(req.ID, -32602, "Prompt not found", fmt.Sprintf("Prompt '%s' not found", getReq.Name))
	}

	// Check if the prompt is blocked
	if s.isPromptBlocked(getReq.Name) {
		s.logger.Warn().
			Str("prompt_name", getReq.Name).
			Msg("Prompt get blocked")
		return s.errorResponse(req.ID, -32603, "Prompt blocked", fmt.Sprintf("Prompt '%s' is blocked by administrator", getReq.Name))
	}

	// Route the prompt get to the appropriate upstream server
	result := s.routePromptGet(prompt, getReq.Name, getReq.Arguments)

	return &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
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
