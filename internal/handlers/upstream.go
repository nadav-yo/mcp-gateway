package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/rs/zerolog"
)

// UpstreamHandler handles CRUD operations for upstream servers
type UpstreamHandler struct {
	db     *database.DB
	server ServerInterface
	logger zerolog.Logger
}

// NewUpstreamHandler creates a new upstream handler
func NewUpstreamHandler(db *database.DB, server ServerInterface) *UpstreamHandler {
	return &UpstreamHandler{
		db:     db,
		server: server,
		logger: logger.GetLogger("upstream-handler"),
	}
}

// CreateUpstreamServerRequest represents the request to create an upstream server
type CreateUpstreamServerRequest struct {
	Name        string             `json:"name" binding:"required"`
	URL         string             `json:"url,omitempty"`
	Command     []string           `json:"command,omitempty"`
	Type        string             `json:"type" binding:"required"`
	Headers     map[string]string  `json:"headers,omitempty"`
	Timeout     string             `json:"timeout,omitempty"`
	Enabled     bool               `json:"enabled"`
	Prefix      string             `json:"prefix,omitempty"`
	Description string             `json:"description,omitempty"`
	Auth        *AuthConfigRequest `json:"auth,omitempty"`
}

// UpdateUpstreamServerRequest represents the request to update an upstream server
type UpdateUpstreamServerRequest struct {
	Name        string             `json:"name,omitempty"`
	URL         string             `json:"url,omitempty"`
	Command     []string           `json:"command,omitempty"`
	Type        string             `json:"type,omitempty"`
	Headers     map[string]string  `json:"headers,omitempty"`
	Timeout     string             `json:"timeout,omitempty"`
	Enabled     *bool              `json:"enabled,omitempty"`
	Prefix      string             `json:"prefix,omitempty"`
	Description string             `json:"description,omitempty"`
	Auth        *AuthConfigRequest `json:"auth,omitempty"`
}

// AuthConfigRequest represents authentication configuration in API requests
type AuthConfigRequest struct {
	Type        string `json:"type"`                   // "bearer", "basic", "api-key"
	BearerToken string `json:"bearer_token,omitempty"` // Bearer token
	Username    string `json:"username,omitempty"`     // For basic auth
	Password    string `json:"password,omitempty"`     // For basic auth
	APIKey      string `json:"api_key,omitempty"`      // API key
	HeaderName  string `json:"header_name,omitempty"`  // Custom header name for API key
}

// ServerInterface defines the methods the upstream handler needs from the server
type ServerInterface interface {
	DisconnectUpstreamServer(serverID int64) error
	ConnectUpstreamServer(serverID int64) error
}

// CreateUpstreamServer handles POST /api/upstream-servers
func (h *UpstreamHandler) CreateUpstreamServer(w http.ResponseWriter, r *http.Request) {
	var req CreateUpstreamServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.Name == "" || req.Type == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: name, type", nil)
		return
	}

	// Validate type-specific requirements
	if req.Type == "stdio" {
		if len(req.Command) == 0 {
			h.writeErrorResponse(w, http.StatusBadRequest, "Command is required for stdio servers", nil)
			return
		}
	} else {
		if req.URL == "" {
			h.writeErrorResponse(w, http.StatusBadRequest, "URL is required for websocket and http servers", nil)
			return
		}
	}

	// Validate type
	if req.Type != "websocket" && req.Type != "http" && req.Type != "stdio" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'websocket', 'http', or 'stdio'", nil)
		return
	}

	// Set defaults
	if req.Timeout == "" {
		req.Timeout = "30s"
	}
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}

	// Create database record with initial status

	record := &database.UpstreamServerRecord{
		Name:        req.Name,
		URL:         req.URL,
		Command:     req.Command,
		Type:        req.Type,
		Headers:     req.Headers,
		Timeout:     req.Timeout,
		Enabled:     req.Enabled,
		Prefix:      req.Prefix,
		Description: req.Description,
	}

	// Add authentication configuration if provided
	if req.Auth != nil {
		record.AuthType = req.Auth.Type
		record.AuthToken = req.Auth.BearerToken
		record.AuthUsername = req.Auth.Username
		record.AuthPassword = req.Auth.Password
		record.AuthAPIKey = req.Auth.APIKey
		record.AuthHeaderName = req.Auth.HeaderName
	}

	created, err := h.db.CreateUpstreamServer(record)
	if err != nil {
		// Check if it's a duplicate name error
		var serverExistsErr database.ErrServerAlreadyExists
		if errors.As(err, &serverExistsErr) {
			h.writeErrorResponse(w, http.StatusConflict, err.Error(), nil)
		} else {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create upstream server", err)
		}
		return
	}

	// If the server is enabled, attempt to connect to it
	if created.Enabled {
		go func() {
			if err := h.server.ConnectUpstreamServer(created.ID); err != nil {
				// Log to server-specific log file
				logger.GetServerLogger().LogServerEvent(created.ID, "error", "Failed to connect to newly created upstream server", map[string]interface{}{
					"error":       err.Error(),
					"server_name": created.Name,
				})
			}
		}()
	}

	h.writeSuccessResponse(w, http.StatusCreated, "Upstream server created successfully", created)

	// Audit log for server creation
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "server_created").
			Str("server_name", created.Name).
			Str("server_type", created.Type).
			Int64("server_id", created.ID).
			Msg("Admin created new server")
	}
}

// GetUpstreamServer handles GET /api/upstream-servers/{id}
func (h *UpstreamHandler) GetUpstreamServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	server, err := h.db.GetUpstreamServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Upstream server not found", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "", server)
}

// ListUpstreamServers handles GET /api/upstream-servers
func (h *UpstreamHandler) ListUpstreamServers(w http.ResponseWriter, r *http.Request) {
	enabledOnly := r.URL.Query().Get("enabled") == "true"

	servers, err := h.db.ListUpstreamServers(enabledOnly)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list upstream servers", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "", map[string]interface{}{
		"servers": servers,
		"count":   len(servers),
	})
}

// UpdateUpstreamServer handles PUT /api/upstream-servers/{id}
func (h *UpstreamHandler) UpdateUpstreamServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	// Get existing server
	existing, err := h.db.GetUpstreamServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Upstream server not found", err)
		return
	}

	var req UpdateUpstreamServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Update fields that are provided
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.URL != "" {
		existing.URL = req.URL
	}
	if req.Command != nil {
		existing.Command = req.Command
	}
	if req.Type != "" {
		if req.Type != "websocket" && req.Type != "http" && req.Type != "stdio" {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'websocket', 'http', or 'stdio'", nil)
			return
		}
		existing.Type = req.Type

		// Validate type-specific requirements
		if req.Type == "stdio" {
			if len(req.Command) == 0 && len(existing.Command) == 0 {
				h.writeErrorResponse(w, http.StatusBadRequest, "Command is required for stdio servers", nil)
				return
			}
		} else {
			if req.URL == "" && existing.URL == "" {
				h.writeErrorResponse(w, http.StatusBadRequest, "URL is required for websocket and http servers", nil)
				return
			}
		}
	}
	if req.Headers != nil {
		existing.Headers = req.Headers
	}
	if req.Timeout != "" {
		existing.Timeout = req.Timeout
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Prefix != "" {
		existing.Prefix = req.Prefix
	}
	if req.Description != "" {
		existing.Description = req.Description
	}

	// Update authentication configuration if provided
	if req.Auth != nil {
		existing.AuthType = req.Auth.Type
		existing.AuthToken = req.Auth.BearerToken
		existing.AuthUsername = req.Auth.Username
		existing.AuthPassword = req.Auth.Password
		existing.AuthAPIKey = req.Auth.APIKey
		existing.AuthHeaderName = req.Auth.HeaderName
	}

	updated, err := h.db.UpdateUpstreamServer(id, existing)
	if err != nil {
		// Check if it's a duplicate name error
		var serverExistsErr database.ErrServerAlreadyExists
		if errors.As(err, &serverExistsErr) {
			h.writeErrorResponse(w, http.StatusConflict, err.Error(), nil)
		} else {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update upstream server", err)
		}
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Upstream server updated successfully", updated)

	// Audit log for server update
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "server_updated").
			Int64("server_id", id).
			Str("server_name", updated.Name).
			Msg("Admin updated server")
	}
}

// DeleteUpstreamServer handles DELETE /api/upstream-servers/{id}
func (h *UpstreamHandler) DeleteUpstreamServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	// Get server info before deletion for audit logging
	serverToDelete, err := h.db.GetUpstreamServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Upstream server not found", err)
		return
	}

	// First disconnect the server if it's currently connected
	if err := h.server.DisconnectUpstreamServer(id); err != nil {
		// Log to server-specific log file
		logger.GetServerLogger().LogServerEvent(id, "error", "Failed to disconnect upstream server during deletion, continuing with database deletion", map[string]interface{}{
			"error": err.Error(),
		})
		// Continue with deletion even if disconnect fails
		// The server might not be connected or might have connection issues
		// We still want to remove it from the database
	}

	// Now delete from database
	if err := h.db.DeleteUpstreamServer(id); err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Failed to delete upstream server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Upstream server deleted successfully", nil)

	// Audit log for server deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "server_deleted").
			Int64("server_id", id).
			Str("server_name", serverToDelete.Name).
			Msg("Admin deleted server")
	}
}

// ToggleUpstreamServer handles POST /api/upstream-servers/{id}/toggle
func (h *UpstreamHandler) ToggleUpstreamServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	// Get existing server
	existing, err := h.db.GetUpstreamServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Upstream server not found", err)
		return
	}

	// Toggle enabled status
	existing.Enabled = !existing.Enabled

	updated, err := h.db.UpdateUpstreamServer(id, existing)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to toggle upstream server", err)
		return
	}

	// If server is being disabled, disconnect it
	if !updated.Enabled {
		// Log that the server has been disabled
		logger.GetServerLogger().LogServerEvent(id, "info", "Server has been disabled", map[string]interface{}{
			"server_name": updated.Name,
		})

		go func() {
			if err := h.server.DisconnectUpstreamServer(id); err != nil {
				// Log to server-specific log file
				logger.GetServerLogger().LogServerEvent(id, "error", "Failed to disconnect upstream server when disabling", map[string]interface{}{
					"error":       err.Error(),
					"server_name": updated.Name,
				})
			}
		}()
	} else {
		// If server is being enabled, connect to it
		go func() {
			if err := h.server.ConnectUpstreamServer(id); err != nil {
				// Log to server-specific log file
				logger.GetServerLogger().LogServerEvent(id, "error", "Failed to connect to upstream server when enabling", map[string]interface{}{
					"error":       err.Error(),
					"server_name": updated.Name,
				})
			}
		}()
	}

	status := "disabled"
	if updated.Enabled {
		status = "enabled"
	}

	h.writeSuccessResponse(w, http.StatusOK, fmt.Sprintf("Upstream server %s successfully", status), updated)
}

// GetServerLog handles GET /api/upstream-servers/{id}/logs
func (h *UpstreamHandler) GetServerLog(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	// Verify server exists
	_, err = h.db.GetUpstreamServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Upstream server not found", err)
		return
	}

	// Get log file path
	logPath := logger.GetServerLogger().GetServerLogPath(id)

	// Check if log file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		h.writeErrorResponse(w, http.StatusNotFound, "Log file not found", nil)
		return
	}

	// Check query parameters for options
	tail := r.URL.Query().Get("tail")
	lines := r.URL.Query().Get("lines")
	download := r.URL.Query().Get("download") == "true"

	if download {
		// Read the entire log file for download
		content, err := os.ReadFile(logPath)
		if err != nil {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read log file for download", err)
			return
		}

		// Serve the file for download
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=server-%d.log", id))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		w.Write(content)
		return
	}

	// Read log file content
	var content []byte
	if tail == "true" && lines != "" {
		// Tail the log file with specified number of lines
		if lineCount, err := strconv.Atoi(lines); err == nil {
			content, err = h.tailLogFile(logPath, lineCount)
			if err != nil {
				h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read log file", err)
				return
			}
		} else {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid lines parameter", err)
			return
		}
	} else {
		// Read entire log file
		content, err = os.ReadFile(logPath)
		if err != nil {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read log file", err)
			return
		}
	}

	h.writeSuccessResponse(w, http.StatusOK, "", map[string]interface{}{
		"content": string(content),
		"path":    logPath,
		"size":    len(content),
	})
}

// ListServerLogs handles GET /api/logs
func (h *UpstreamHandler) ListServerLogs(w http.ResponseWriter, r *http.Request) {
	logFiles, err := logger.GetServerLogger().ListServerLogs()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list log files", err)
		return
	}

	// Get file information for each log
	var logs []map[string]interface{}
	for _, logFile := range logFiles {
		logPath := filepath.Join("logs", logFile)
		if info, err := os.Stat(logPath); err == nil {
			// Extract server ID from filename
			var serverID int64
			if n, err := fmt.Sscanf(logFile, "server-%d.log", &serverID); n == 1 && err == nil {
				if server, err := h.db.GetUpstreamServer(serverID); err == nil {
					logs = append(logs, map[string]interface{}{
						"filename":    logFile,
						"server_id":   serverID,
						"server_name": server.Name,
						"size":        info.Size(),
						"modified":    info.ModTime(),
					})
				}
			}
		}
	}

	h.writeSuccessResponse(w, http.StatusOK, "", map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// tailLogFile reads the last n lines from a log file
func (h *UpstreamHandler) tailLogFile(filepath string, lines int) ([]byte, error) {
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

// RegisterRoutes registers all upstream server routes
func (h *UpstreamHandler) RegisterRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()

	// Upstream servers CRUD
	api.HandleFunc("/upstream-servers", h.CreateUpstreamServer).Methods("POST")
	api.HandleFunc("/upstream-servers", h.ListUpstreamServers).Methods("GET")
	api.HandleFunc("/upstream-servers/{id:[0-9]+}", h.GetUpstreamServer).Methods("GET")
	api.HandleFunc("/upstream-servers/{id:[0-9]+}", h.UpdateUpstreamServer).Methods("PUT")
	api.HandleFunc("/upstream-servers/{id:[0-9]+}", h.DeleteUpstreamServer).Methods("DELETE")
	api.HandleFunc("/upstream-servers/{id:[0-9]+}/toggle", h.ToggleUpstreamServer).Methods("POST")

	// Server logs endpoints
	api.HandleFunc("/upstream-servers/{id:[0-9]+}/logs", h.GetServerLog).Methods("GET")
	api.HandleFunc("/logs", h.ListServerLogs).Methods("GET")
}

// Helper methods
func (h *UpstreamHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *UpstreamHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: false,
		Message: message,
	}

	if err != nil {
		response.Error = err.Error()
	}

	json.NewEncoder(w).Encode(response)
}
