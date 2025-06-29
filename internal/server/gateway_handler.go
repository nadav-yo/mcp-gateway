package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/nadav-yo/mcp-gateway/internal/client"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

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

// handleGenericLog handles requests for generic log files
func (s *Server) handleGenericLog(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]
	
	// Security: only allow specific log files
	allowedLogs := map[string]bool{
		"request.log": true,
		"audit.log":   true,
	}
	
	if !allowedLogs[filename] {
		http.Error(w, "Log file not found", http.StatusNotFound)
		return
	}
	
	logPath := filepath.Join("logs", filename)
	
	// Check if download is requested
	if r.URL.Query().Get("download") == "true" {
		// Serve file for download
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, logPath)
		return
	}
	
	// Read log content
	content, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty content
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"content": "",
				},
			})
			return
		}
		s.logger.Error().Err(err).Str("filename", filename).Msg("Failed to read log file")
		http.Error(w, "Failed to read log file", http.StatusInternalServerError)
		return
	}
	
	contentStr := string(content)
	
	// Handle tail option
	if r.URL.Query().Get("tail") == "true" {
		lines := strings.Split(contentStr, "\n")
		lineCount := 100 // default
		if linesParam := r.URL.Query().Get("lines"); linesParam != "" {
			if parsed, err := strconv.Atoi(linesParam); err == nil && parsed > 0 {
				lineCount = parsed
			}
		}
		
		if len(lines) > lineCount {
			lines = lines[len(lines)-lineCount:]
		}
		contentStr = strings.Join(lines, "\n")
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"content": contentStr,
		},
	})
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

// handleCuratedServers handles requests for curated MCP servers list
func (s *Server) handleCuratedServers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Get curated servers from database
	curatedServers, err := s.db.ListCuratedServers()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to load curated servers from database")
		http.Error(w, fmt.Sprintf("Failed to load curated servers: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Convert to API format (maintaining backward compatibility)
	apiServers := make([]map[string]interface{}, len(curatedServers))
	for i, server := range curatedServers {
		apiServer := map[string]interface{}{
			"id":          server.ID,
			"name":        server.Name,
			"type":        server.Type,
			"description": server.Description,
		}
		
		// Add type-specific fields
		if server.Type == "stdio" {
			apiServer["command"] = server.Command
			if len(server.Args) > 0 {
				apiServer["args"] = server.Args
			}
		} else {
			apiServer["url"] = server.URL
		}
		
		apiServers[i] = apiServer
	}
	
	response := map[string]interface{}{
		"servers":    apiServers,
		"total":      len(apiServers),
		"updated_at": time.Now().Format(time.RFC3339),
		"version":    "2.0", // Increment version to indicate it's now database-backed
	}
	
	s.logger.Info().
		Int("server_count", len(apiServers)).
		Str("remote_addr", r.RemoteAddr).
		Msg("Served curated servers list from database")
	
	json.NewEncoder(w).Encode(response)
}
