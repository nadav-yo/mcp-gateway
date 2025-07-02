package server

import (
	"encoding/json"
	"fmt"
	"io"
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
		// Get the server ID for this client
		var serverID int64
		for id, client := range s.clientsByID {
			if client == mcpClient {
				serverID = id
				break
			}
		}

		// Get blocked tools for this server
		blockedToolsSet := make(map[string]bool)
		if serverID > 0 {
			if blockedTools, err := s.db.GetBlockedToolsSet(serverID, "servers"); err == nil {
				blockedToolsSet = blockedTools
			}
		}

		// Get blocked prompts for this server
		blockedPromptsSet := make(map[string]bool)
		if serverID > 0 {
			if blockedPrompts, err := s.db.GetBlockedPromptsSet(serverID, "servers"); err == nil {
				blockedPromptsSet = blockedPrompts
			}
		}

		// Get blocked resources for this server
		blockedResourcesSet := make(map[string]bool)
		if serverID > 0 {
			if blockedResources, err := s.db.GetBlockedResourcesSet(serverID, "servers"); err == nil {
				blockedResourcesSet = blockedResources
			}
		}

		tools := mcpClient.GetTools()
		toolDetails := make([]map[string]interface{}, 0, len(tools))
		for toolName, tool := range tools {
			isBlocked := blockedToolsSet[toolName]
			toolDetails = append(toolDetails, map[string]interface{}{
				"name":        toolName,
				"description": tool.Description,
				"blocked":     isBlocked,
			})
		}

		prompts := mcpClient.GetPrompts()
		promptDetails := make([]map[string]interface{}, 0, len(prompts))
		for promptName, prompt := range prompts {
			isBlocked := blockedPromptsSet[promptName]
			promptDetails = append(promptDetails, map[string]interface{}{
				"name":        promptName,
				"description": prompt.Description,
				"blocked":     isBlocked,
				"serverId":    serverID,
				"serverType":  "servers",
			})
		}

		resources := mcpClient.GetResources()
		resourceDetails := make([]map[string]interface{}, 0, len(resources))
		for resourceName, resource := range resources {
			isBlocked := blockedResourcesSet[resourceName]
			resourceDetails = append(resourceDetails, map[string]interface{}{
				"name":        resourceName,
				"description": resource.Description,
				"uri":         resource.URI,
				"blocked":     isBlocked,
				"serverId":    serverID,
				"serverType":  "servers",
			})
		}

		upstream := map[string]interface{}{
			"name":             name,
			"connected":        mcpClient.IsConnected(),
			"tools":            len(tools),
			"tool_details":     toolDetails,
			"resources":        len(resources),
			"resource_details": resourceDetails,
			"prompts":          len(prompts),
			"prompt_details":   promptDetails,
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
		"total_prompts":    len(s.prompts),
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

	// Check if log file exists
	fileInfo, err := os.Stat(logPath)
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

	// Parse query parameters
	query := r.URL.Query()
	download := query.Get("download") == "true"
	tail := query.Get("tail") == "true"
	linesParam := query.Get("lines")
	pageParam := query.Get("page")
	limitParam := query.Get("limit")
	search := query.Get("search")
	level := query.Get("level")

	// Check file size and warn if too large (>5MB)
	const maxDisplaySize = 5 * 1024 * 1024 // 5MB
	fileSize := fileInfo.Size()

	if download {
		// Serve file for download
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, logPath)
		return
	}

	// Handle streaming for large files
	if query.Get("stream") == "true" {
		s.streamLogFile(w, r, logPath, search, level)
		return
	}

	// Default behavior for large files - force tail mode
	if fileSize > maxDisplaySize && !tail && pageParam == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Log file is too large (%d MB). Use tail=true, pagination, or download.", fileSize/(1024*1024)),
			"data": map[string]interface{}{
				"file_size":        fileSize,
				"max_display_size": maxDisplaySize,
				"suggestions": []string{
					"Add ?tail=true&lines=100 for recent logs",
					"Add ?page=1&limit=100 for pagination",
					"Add ?download=true to download full file",
					"Add ?stream=true for streaming",
				},
			},
		})
		return
	}

	var contentStr string

	// Handle pagination
	if pageParam != "" && limitParam != "" {
		page, err := strconv.Atoi(pageParam)
		if err != nil || page < 1 {
			http.Error(w, "Invalid page parameter", http.StatusBadRequest)
			return
		}
		limit, err := strconv.Atoi(limitParam)
		if err != nil || limit < 1 || limit > 1000 {
			http.Error(w, "Invalid limit parameter (1-1000)", http.StatusBadRequest)
			return
		}

		content, err := s.getPaginatedLogContent(logPath, page, limit, search, level)
		if err != nil {
			s.logger.Error().Err(err).Str("filename", filename).Msg("Failed to read paginated log file")
			http.Error(w, "Failed to read log file", http.StatusInternalServerError)
			return
		}
		contentStr = string(content)
	} else if tail {
		// Handle tail mode
		lineCount := 100 // default
		if linesParam != "" {
			if parsed, err := strconv.Atoi(linesParam); err == nil && parsed > 0 && parsed <= 10000 {
				lineCount = parsed
			}
		}

		content, err := s.tailLogFile(logPath, lineCount)
		if err != nil {
			s.logger.Error().Err(err).Str("filename", filename).Msg("Failed to tail log file")
			http.Error(w, "Failed to read log file", http.StatusInternalServerError)
			return
		}
		contentStr = string(content)
	} else {
		// Read entire file (only for small files)
		content, err := os.ReadFile(logPath)
		if err != nil {
			s.logger.Error().Err(err).Str("filename", filename).Msg("Failed to read log file")
			http.Error(w, "Failed to read log file", http.StatusInternalServerError)
			return
		}
		contentStr = string(content)
	}

	// Apply search and level filtering if specified
	if search != "" || level != "" {
		contentStr = string(s.filterLogContent([]byte(contentStr), search, level))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"content":   contentStr,
			"file_size": fileSize,
			"filtered":  search != "" || level != "",
		},
	})
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"name":    s.config.MCP.Name,
		"version": s.config.MCP.Version,
	})
}

// handleInfo handles info requests
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	info := map[string]interface{}{
		"name":         s.config.MCP.Name,
		"description":  s.config.MCP.Description,
		"version":      s.config.MCP.Version,
		"capabilities": s.config.MCP.Capabilities,
		"tools":        len(s.tools),
		"resources":    len(s.resources),
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

// streamLogFile streams log content in chunks for large files
func (s *Server) streamLogFile(w http.ResponseWriter, r *http.Request, logPath, search, level string) {
	file, err := os.Open(logPath)
	if err != nil {
		http.Error(w, "Failed to open log file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set headers for streaming
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	// Stream file in chunks
	const chunkSize = 8192
	buffer := make([]byte, chunkSize)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			// Apply filtering if needed
			if search != "" || level != "" {
				chunk = s.filterLogContent(chunk, search, level)
			}
			if len(chunk) > 0 {
				w.Write(chunk)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
	}
}

// getPaginatedLogContent returns a specific page of log content
func (s *Server) getPaginatedLogContent(logPath string, page, limit int, search, level string) ([]byte, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read all lines (for simplicity - could be optimized for very large files)
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	// Apply filtering first
	if search != "" || level != "" {
		filteredLines := []string{}
		for _, line := range lines {
			if s.matchesFilter(line, search, level) {
				filteredLines = append(filteredLines, line)
			}
		}
		lines = filteredLines
	}

	// Calculate pagination
	start := (page - 1) * limit
	end := start + limit

	if start >= len(lines) {
		return []byte(""), nil
	}
	if end > len(lines) {
		end = len(lines)
	}

	pageLines := lines[start:end]
	return []byte(strings.Join(pageLines, "\n")), nil
}

// tailLogFile reads the last n lines from a log file
func (s *Server) tailLogFile(filepath string, lines int) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := stat.Size()

	// Read from the end of the file
	const bufferSize = 8192
	var result []string
	var offset int64

	for {
		// Calculate read position
		readSize := int64(bufferSize)
		if offset+readSize > fileSize {
			readSize = fileSize - offset
		}
		if readSize <= 0 {
			break
		}

		// Read chunk from end
		buffer := make([]byte, readSize)
		_, err := file.ReadAt(buffer, fileSize-offset-readSize)
		if err != nil && err != io.EOF {
			return nil, err
		}

		// Split into lines and prepend to result
		chunk := string(buffer)
		chunkLines := strings.Split(chunk, "\n")

		// Prepend lines (except the first one which might be partial)
		for i := len(chunkLines) - 1; i >= 0; i-- {
			if len(chunkLines[i]) > 0 || (i == len(chunkLines)-1 && offset == 0) {
				result = append([]string{chunkLines[i]}, result...)
				if len(result) >= lines {
					break
				}
			}
		}

		if len(result) >= lines {
			break
		}

		offset += readSize
		if offset >= fileSize {
			break
		}
	}

	// Take only the requested number of lines
	if len(result) > lines {
		result = result[len(result)-lines:]
	}

	return []byte(strings.Join(result, "\n")), nil
}

// filterLogContent applies search and level filters to log content
func (s *Server) filterLogContent(content []byte, search, level string) []byte {
	if search == "" && level == "" {
		return content
	}

	lines := strings.Split(string(content), "\n")
	filteredLines := []string{}

	for _, line := range lines {
		if s.matchesFilter(line, search, level) {
			filteredLines = append(filteredLines, line)
		}
	}

	return []byte(strings.Join(filteredLines, "\n"))
}

// matchesFilter checks if a log line matches the search and level criteria
func (s *Server) matchesFilter(line, search, level string) bool {
	// Search filter
	if search != "" {
		searchLower := strings.ToLower(search)
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, searchLower) {
			return false
		}
	}

	// Level filter (for JSON logs)
	if level != "" && level != "all" {
		// Try to parse as JSON to extract level
		var logEntry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &logEntry); err == nil {
			if logLevel, exists := logEntry["level"]; exists {
				if logLevelStr, ok := logLevel.(string); ok {
					if strings.ToLower(logLevelStr) != strings.ToLower(level) {
						return false
					}
				}
			}
		} else {
			// For non-JSON logs, do simple text matching
			levelLower := strings.ToLower(level)
			lineLower := strings.ToLower(line)
			if !strings.Contains(lineLower, levelLower) {
				return false
			}
		}
	}

	return true
}
