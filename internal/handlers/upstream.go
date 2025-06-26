package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/nadav-yo/mcp-gateway/internal/database"
)

// UpstreamHandler handles CRUD operations for upstream servers
type UpstreamHandler struct {
	db *database.DB
}

// NewUpstreamHandler creates a new upstream handler
func NewUpstreamHandler(db *database.DB) *UpstreamHandler {
	return &UpstreamHandler{db: db}
}

// CreateUpstreamServerRequest represents the request to create an upstream server
type CreateUpstreamServerRequest struct {
	Name        string            `json:"name" binding:"required"`
	URL         string            `json:"url" binding:"required"`
	Type        string            `json:"type" binding:"required"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     string            `json:"timeout,omitempty"`
	Enabled     bool              `json:"enabled"`
	Prefix      string            `json:"prefix,omitempty"`
	Description string            `json:"description,omitempty"`
	Auth        *AuthConfigRequest `json:"auth,omitempty"`
}

// UpdateUpstreamServerRequest represents the request to update an upstream server
type UpdateUpstreamServerRequest struct {
	Name        string            `json:"name,omitempty"`
	URL         string            `json:"url,omitempty"`
	Type        string            `json:"type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     string            `json:"timeout,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
	Prefix      string            `json:"prefix,omitempty"`
	Description string            `json:"description,omitempty"`
	Auth        *AuthConfigRequest `json:"auth,omitempty"`
}

// AuthConfigRequest represents authentication configuration in API requests
type AuthConfigRequest struct {
	Type         string `json:"type"`                    // "bearer", "basic", "api-key"
	BearerToken  string `json:"bearer_token,omitempty"`  // Bearer token
	Username     string `json:"username,omitempty"`      // For basic auth
	Password     string `json:"password,omitempty"`      // For basic auth
	APIKey       string `json:"api_key,omitempty"`       // API key
	HeaderName   string `json:"header_name,omitempty"`   // Custom header name for API key
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// CreateUpstreamServer handles POST /api/upstream-servers
func (h *UpstreamHandler) CreateUpstreamServer(w http.ResponseWriter, r *http.Request) {
	var req CreateUpstreamServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.Name == "" || req.URL == "" || req.Type == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: name, url, type", nil)
		return
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

	// Create database record
	record := &database.UpstreamServerRecord{
		Name:        req.Name,
		URL:         req.URL,
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
		h.writeErrorResponse(w, http.StatusConflict, "Failed to create upstream server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusCreated, "Upstream server created successfully", created)
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
	if req.Type != "" {
		if req.Type != "websocket" && req.Type != "http" && req.Type != "stdio" {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'websocket', 'http', or 'stdio'", nil)
			return
		}
		existing.Type = req.Type
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
		h.writeErrorResponse(w, http.StatusConflict, "Failed to update upstream server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Upstream server updated successfully", updated)
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

	if err := h.db.DeleteUpstreamServer(id); err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Failed to delete upstream server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Upstream server deleted successfully", nil)
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

	status := "disabled"
	if updated.Enabled {
		status = "enabled"
	}

	h.writeSuccessResponse(w, http.StatusOK, fmt.Sprintf("Upstream server %s successfully", status), updated)
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
