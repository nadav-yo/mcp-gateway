package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/rs/zerolog"
)

// BlockedResourceHandler handles CRUD operations for blocked resources
type BlockedResourceHandler struct {
	db                      *database.DB
	logger                  zerolog.Logger
	invalidateCacheCallback func() // Callback to invalidate server cache
}

// NewBlockedResourceHandler creates a new blocked resource handler
func NewBlockedResourceHandler(db *database.DB) *BlockedResourceHandler {
	return &BlockedResourceHandler{
		db:     db,
		logger: logger.GetLogger("blocked-resource-handler"),
	}
}

// NewBlockedResourceHandlerWithCallback creates a new blocked resource handler with cache invalidation callback
func NewBlockedResourceHandlerWithCallback(db *database.DB, invalidateCallback func()) *BlockedResourceHandler {
	return &BlockedResourceHandler{
		db:                      db,
		logger:                  logger.GetLogger("blocked-resource-handler"),
		invalidateCacheCallback: invalidateCallback,
	}
}

// CreateBlockedResourceRequest represents the request to create a blocked resource
type CreateBlockedResourceRequest struct {
	ServerID     int64  `json:"server_id" binding:"required"`
	Type         string `json:"type" binding:"required"` // "servers" or "curated_servers"
	ResourceName string `json:"resource_name" binding:"required"`
}

// CreateBlockedResource handles POST /api/blocked-resources
func (h *BlockedResourceHandler) CreateBlockedResource(w http.ResponseWriter, r *http.Request) {
	var req CreateBlockedResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.ServerID == 0 || req.Type == "" || req.ResourceName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: server_id, type, resource_name", nil)
		return
	}

	// Validate type
	if req.Type != "servers" && req.Type != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	// Create database record
	record := &database.BlockedResourceRecord{
		ServerID:     req.ServerID,
		Type:         req.Type,
		ResourceName: req.ResourceName,
	}

	created, err := h.db.CreateBlockedResource(record)
	if err != nil {
		h.writeErrorResponse(w, http.StatusConflict, "Failed to create blocked resource", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusCreated, "Blocked resource created successfully", created)

	// Invalidate cache after creating blocked resource
	if h.invalidateCacheCallback != nil {
		h.invalidateCacheCallback()
	}

	// Audit log for blocked resource creation
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.Audit(r.Context()).Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_resource_created").
			Int64("server_id", created.ServerID).
			Str("server_type", created.Type).
			Str("resource_name", created.ResourceName).
			Int64("blocked_resource_id", created.ID).
			Msg("Admin created new blocked resource")
	}
}

// GetBlockedResource handles GET /api/blocked-resources/{id}
func (h *BlockedResourceHandler) GetBlockedResource(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing blocked resource ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid blocked resource ID", err)
		return
	}

	blockedResource, err := h.db.GetBlockedResource(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Blocked resource not found", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked resource retrieved successfully", blockedResource)
}

// ListBlockedResources handles GET /api/blocked-resources
func (h *BlockedResourceHandler) ListBlockedResources(w http.ResponseWriter, r *http.Request) {
	// Check for query parameters to filter by server
	serverIDStr := r.URL.Query().Get("server_id")
	serverType := r.URL.Query().Get("type")

	if serverIDStr != "" && serverType != "" {
		// List blocked resources for specific server
		serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
			return
		}

		blockedResources, err := h.db.ListBlockedResourcesByServerID(serverID, serverType)
		if err != nil {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked resources", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusOK, "Blocked resources retrieved successfully", blockedResources)
		return
	}

	// List all blocked resources
	blockedResources, err := h.db.ListAllBlockedResources()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked resources", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked resources retrieved successfully", blockedResources)
}

// ListBlockedResourcesByServer handles GET /api/blocked-resources/server/{server_id}?type={type}
func (h *BlockedResourceHandler) ListBlockedResourcesByServer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverIDStr, exists := vars["server_id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	serverType := r.URL.Query().Get("type")
	if serverType == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing type parameter", nil)
		return
	}

	if serverType != "servers" && serverType != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	blockedResources, err := h.db.ListBlockedResourcesByServerID(serverID, serverType)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked resources", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked resources retrieved successfully", blockedResources)
}

// DeleteBlockedResource handles DELETE /api/blocked-resources/{id}
func (h *BlockedResourceHandler) DeleteBlockedResource(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing blocked resource ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid blocked resource ID", err)
		return
	}

	// Get blocked resource info for audit log before deletion
	blockedResource, err := h.db.GetBlockedResource(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Blocked resource not found", err)
		return
	}

	err = h.db.DeleteBlockedResource(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete blocked resource", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked resource deleted successfully", nil)

	// Invalidate cache after deleting blocked resource
	if h.invalidateCacheCallback != nil {
		h.invalidateCacheCallback()
	}

	// Audit log for blocked resource deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.Audit(r.Context()).Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_resource_deleted").
			Int64("server_id", blockedResource.ServerID).
			Str("server_type", blockedResource.Type).
			Str("resource_name", blockedResource.ResourceName).
			Int64("blocked_resource_id", blockedResource.ID).
			Msg("Admin deleted blocked resource")
	}
}

// DeleteBlockedResourceByDetails handles DELETE /api/blocked-resources/server/{server_id}/resource/{resource_name}?type={type}
func (h *BlockedResourceHandler) DeleteBlockedResourceByDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverIDStr, exists := vars["server_id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	resourceName, exists := vars["resource_name"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing resource name", nil)
		return
	}

	serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
		return
	}

	serverType := r.URL.Query().Get("type")
	if serverType == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing type parameter", nil)
		return
	}

	if serverType != "servers" && serverType != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	err = h.db.DeleteBlockedResourceByDetails(serverID, serverType, resourceName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Failed to delete blocked resource", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked resource deleted successfully", nil)

	// Invalidate cache after deleting blocked resource
	if h.invalidateCacheCallback != nil {
		h.invalidateCacheCallback()
	}

	// Audit log for blocked resource deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.Audit(r.Context()).Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_resource_deleted").
			Int64("server_id", serverID).
			Str("server_type", serverType).
			Str("resource_name", resourceName).
			Msg("Admin deleted blocked resource by details")
	}
}

// ToggleBlockedResource handles POST /api/blocked-resources/toggle
func (h *BlockedResourceHandler) ToggleBlockedResource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID     int64  `json:"server_id" binding:"required"`
		Type         string `json:"type" binding:"required"` // "servers" or "curated_servers"
		ResourceName string `json:"resource_name" binding:"required"`
		Block        bool   `json:"block"` // true to block, false to unblock
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.ServerID == 0 || req.Type == "" || req.ResourceName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: server_id, type, resource_name", nil)
		return
	}

	// Validate type
	if req.Type != "servers" && req.Type != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	if req.Block {
		// Block the resource
		record := &database.BlockedResourceRecord{
			ServerID:     req.ServerID,
			Type:         req.Type,
			ResourceName: req.ResourceName,
		}

		created, err := h.db.CreateBlockedResource(record)
		if err != nil {
			// If it's already blocked, that's okay
			if strings.Contains(err.Error(), "already blocked") {
				h.writeSuccessResponse(w, http.StatusOK, "Resource is already blocked", nil)
				return
			}
			h.writeErrorResponse(w, http.StatusConflict, "Failed to block resource", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusCreated, "Resource blocked successfully", created)

		// Invalidate cache after blocking resource
		if h.invalidateCacheCallback != nil {
			h.invalidateCacheCallback()
		}

		// Audit log for blocking
		if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
			logger.Audit(r.Context()).Info().
				Str("admin_username", user.Username).
				Str("action", "resource_blocked").
				Int64("server_id", created.ServerID).
				Str("server_type", created.Type).
				Str("resource_name", created.ResourceName).
				Msg("Admin blocked resource")
		}
	} else {
		// Unblock the resource
		err := h.db.DeleteBlockedResourceByDetails(req.ServerID, req.Type, req.ResourceName)
		if err != nil {
			// If it's not blocked, that's okay
			if strings.Contains(err.Error(), "not found") {
				h.writeSuccessResponse(w, http.StatusOK, "Resource is not blocked", nil)
				return
			}
			h.writeErrorResponse(w, http.StatusNotFound, "Failed to unblock resource", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusOK, "Resource unblocked successfully", nil)

		// Invalidate cache after unblocking resource
		if h.invalidateCacheCallback != nil {
			h.invalidateCacheCallback()
		}

		// Audit log for unblocking
		if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
			logger.Audit(r.Context()).Info().
				Str("admin_username", user.Username).
				Str("action", "resource_unblocked").
				Int64("server_id", req.ServerID).
				Str("server_type", req.Type).
				Str("resource_name", req.ResourceName).
				Msg("Admin unblocked resource")
		}
	}
}

// RegisterAdminRoutes registers admin-only blocked resource routes
func (h *BlockedResourceHandler) RegisterAdminRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()

	// Admin-only blocked resources CRUD
	api.HandleFunc("/blocked-resources", h.CreateBlockedResource).Methods("POST")
	api.HandleFunc("/blocked-resources", h.ListBlockedResources).Methods("GET")
	api.HandleFunc("/blocked-resources/{id:[0-9]+}", h.GetBlockedResource).Methods("GET")
	api.HandleFunc("/blocked-resources/{id:[0-9]+}", h.DeleteBlockedResource).Methods("DELETE")

	// Toggle endpoint for blocking/unblocking resources
	api.HandleFunc("/blocked-resources/toggle", h.ToggleBlockedResource).Methods("POST")

	// Additional convenience endpoints
	api.HandleFunc("/blocked-resources/server/{server_id:[0-9]+}", h.ListBlockedResourcesByServer).Methods("GET")
	api.HandleFunc("/blocked-resources/server/{server_id:[0-9]+}/resource/{resource_name}", h.DeleteBlockedResourceByDetails).Methods("DELETE")
}

// Helper methods
func (h *BlockedResourceHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *BlockedResourceHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
