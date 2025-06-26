package server

import (
	"fmt"

	"github.com/nadav-yo/mcp-gateway/internal/client"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

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
		
		mcpClient := client.NewMCPClientWithID(upstream, serverRecord.ID)
		
		if err := mcpClient.Connect(); err != nil {
			// Log to server-specific log file
			logger.GetServerLogger().LogServerEvent(serverRecord.ID, "error", "Failed to connect to upstream server", map[string]interface{}{
				"error": err.Error(),
				"upstream": upstream.Name,
				"type": upstream.Type,
			})
			
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

		// Log successful connection to server-specific log file
		logger.GetServerLogger().LogServerEvent(serverRecord.ID, "info", "Successfully connected to upstream server", map[string]interface{}{
			"upstream": upstream.Name,
			"type": upstream.Type,
		})
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
	// Log connection attempt to server-specific log file
	logger.GetServerLogger().LogServerEvent(serverRecord.ID, "info", "Connecting to upstream server", map[string]interface{}{
		"upstream": upstream.Name,
		"type": upstream.Type,
	})
	if upstream.Type == "stdio" {
		s.db.UpdateUpstreamServerStatus(serverRecord.ID, "starting")
	}
	
	mcpClient := client.NewMCPClientWithID(upstream, serverRecord.ID)
	
	if err := mcpClient.Connect(); err != nil {
		// Log to server-specific log file
		logger.GetServerLogger().LogServerEvent(serverRecord.ID, "error", "Failed to connect to upstream server", map[string]interface{}{
			"error": err.Error(),
			"upstream": upstream.Name,
			"type": upstream.Type,
		})
		
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

	// Log successful connection to server-specific log file
	logger.GetServerLogger().LogServerEvent(serverRecord.ID, "info", "Successfully connected to upstream server", map[string]interface{}{
		"upstream": upstream.Name,
		"type": upstream.Type,
	})
	
	// Update stats
	s.updateStats()
	
	return nil
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
			// Log to server-specific log file
			logger.GetServerLogger().LogServerEvent(serverID, "error", "Error closing connection to upstream server", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			// Log to server-specific log file
			logger.GetServerLogger().LogServerEvent(serverID, "debug", "Upstream server process exited", map[string]interface{}{
				"error": err.Error(),
			})
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
	
	// Log disconnection to server-specific log file
	logger.GetServerLogger().LogServerEvent(serverID, "info", "Disconnected upstream server", map[string]interface{}{
		"server_id": serverID,
	})
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
