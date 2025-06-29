package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/rs/zerolog"
)

// CuratedServerHandler handles CRUD operations for curated servers
type CuratedServerHandler struct {
	db     *database.DB
	logger zerolog.Logger
}

// NewCuratedServerHandler creates a new curated server handler
func NewCuratedServerHandler(db *database.DB) *CuratedServerHandler {
	return &CuratedServerHandler{
		db:     db,
		logger: logger.GetLogger("curated-server-handler"),
	}
}

// CreateCuratedServerRequest represents the request to create a curated server
type CreateCuratedServerRequest struct {
	Name        string   `json:"name" binding:"required"`
	Type        string   `json:"type" binding:"required"`
	URL         string   `json:"url,omitempty"`
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
	Description string   `json:"description,omitempty"`
}

// UpdateCuratedServerRequest represents the request to update a curated server
type UpdateCuratedServerRequest struct {
	Name        string   `json:"name,omitempty"`
	Type        string   `json:"type,omitempty"`
	URL         string   `json:"url,omitempty"`
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
	Description string   `json:"description,omitempty"`
}

// CreateCuratedServer handles POST /api/curated-servers
func (h *CuratedServerHandler) CreateCuratedServer(w http.ResponseWriter, r *http.Request) {
	var req CreateCuratedServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.Name == "" || req.Type == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: name, type", nil)
		return
	}

	// Validate type
	if req.Type != "stdio" && req.Type != "http" && req.Type != "ws" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'stdio', 'http', or 'ws'", nil)
		return
	}

	// Validate type-specific requirements
	if req.Type == "stdio" {
		if req.Command == "" {
			h.writeErrorResponse(w, http.StatusBadRequest, "Command is required for stdio servers", nil)
			return
		}
	} else {
		if req.URL == "" {
			h.writeErrorResponse(w, http.StatusBadRequest, "URL is required for http and ws servers", nil)
			return
		}
	}

	// Set defaults
	if req.Args == nil {
		req.Args = []string{}
	}

	// Create database record
	record := &database.CuratedServerRecord{
		Name:        req.Name,
		Type:        req.Type,
		URL:         req.URL,
		Command:     req.Command,
		Args:        req.Args,
		Description: req.Description,
	}

	created, err := h.db.CreateCuratedServer(record)
	if err != nil {
		h.writeErrorResponse(w, http.StatusConflict, "Failed to create curated server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusCreated, "Curated server created successfully", created)

	// Audit log for server creation
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "curated_server_created").
			Str("server_name", created.Name).
			Str("server_type", created.Type).
			Int64("server_id", created.ID).
			Msg("Admin created new curated server")
	}
}

// GetCuratedServer handles GET /api/curated-servers/{id}
func (h *CuratedServerHandler) GetCuratedServer(w http.ResponseWriter, r *http.Request) {
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

	server, err := h.db.GetCuratedServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Curated server not found", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Curated server retrieved successfully", server)
}

// ListCuratedServers handles GET /api/curated-servers
func (h *CuratedServerHandler) ListCuratedServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.db.ListCuratedServers()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list curated servers", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Curated servers retrieved successfully", servers)
}

// UpdateCuratedServer handles PUT /api/curated-servers/{id}
func (h *CuratedServerHandler) UpdateCuratedServer(w http.ResponseWriter, r *http.Request) {
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

	var req UpdateCuratedServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate type if provided
	if req.Type != "" && req.Type != "stdio" && req.Type != "http" && req.Type != "ws" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'stdio', 'http', or 'ws'", nil)
		return
	}

	// Create update record
	updates := &database.CuratedServerRecord{
		Name:        req.Name,
		Type:        req.Type,
		URL:         req.URL,
		Command:     req.Command,
		Args:        req.Args,
		Description: req.Description,
	}

	updated, err := h.db.UpdateCuratedServer(id, updates)
	if err != nil {
		h.writeErrorResponse(w, http.StatusConflict, "Failed to update curated server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Curated server updated successfully", updated)

	// Audit log for server update
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "curated_server_updated").
			Str("server_name", updated.Name).
			Str("server_type", updated.Type).
			Int64("server_id", updated.ID).
			Msg("Admin updated curated server")
	}
}

// DeleteCuratedServer handles DELETE /api/curated-servers/{id}
func (h *CuratedServerHandler) DeleteCuratedServer(w http.ResponseWriter, r *http.Request) {
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

	// Get server info for audit log before deletion
	server, err := h.db.GetCuratedServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Curated server not found", err)
		return
	}

	err = h.db.DeleteCuratedServer(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete curated server", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Curated server deleted successfully", nil)

	// Audit log for server deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "curated_server_deleted").
			Str("server_name", server.Name).
			Str("server_type", server.Type).
			Int64("server_id", server.ID).
			Msg("Admin deleted curated server")
	}
}

// RegisterAdminRoutes registers admin-only curated server routes
func (h *CuratedServerHandler) RegisterAdminRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()

	// Admin-only curated servers CRUD
	api.HandleFunc("/curated-servers", h.CreateCuratedServer).Methods("POST")
	api.HandleFunc("/curated-servers/{id:[0-9]+}", h.UpdateCuratedServer).Methods("PUT")
	api.HandleFunc("/curated-servers/{id:[0-9]+}", h.DeleteCuratedServer).Methods("DELETE")
}

// RegisterPublicRoutes registers public curated server routes (read-only)
func (h *CuratedServerHandler) RegisterPublicRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()

	// Public read-only curated servers endpoints
	api.HandleFunc("/curated-servers", h.ListCuratedServers).Methods("GET")
	api.HandleFunc("/curated-servers/{id:[0-9]+}", h.GetCuratedServer).Methods("GET")
}

// Helper methods
func (h *CuratedServerHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *CuratedServerHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
