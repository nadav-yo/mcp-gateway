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

// BlockedPromptHandler handles CRUD operations for blocked prompts
type BlockedPromptHandler struct {
	db                      *database.DB
	logger                  zerolog.Logger
	invalidateCacheCallback func() // Callback to invalidate server cache
}

// NewBlockedPromptHandler creates a new blocked prompt handler
func NewBlockedPromptHandler(db *database.DB) *BlockedPromptHandler {
	return &BlockedPromptHandler{
		db:     db,
		logger: logger.GetLogger("blocked-prompt-handler"),
	}
}

// NewBlockedPromptHandlerWithCallback creates a new blocked prompt handler with cache invalidation callback
func NewBlockedPromptHandlerWithCallback(db *database.DB, invalidateCallback func()) *BlockedPromptHandler {
	return &BlockedPromptHandler{
		db:                      db,
		logger:                  logger.GetLogger("blocked-prompt-handler"),
		invalidateCacheCallback: invalidateCallback,
	}
}

// CreateBlockedPromptRequest represents the request to create a blocked prompt
type CreateBlockedPromptRequest struct {
	ServerID   int64  `json:"server_id" binding:"required"`
	Type       string `json:"type" binding:"required"` // "servers" or "curated_servers"
	PromptName string `json:"prompt_name" binding:"required"`
}

// CreateBlockedPrompt handles POST /api/blocked-prompts
func (h *BlockedPromptHandler) CreateBlockedPrompt(w http.ResponseWriter, r *http.Request) {
	var req CreateBlockedPromptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.ServerID == 0 || req.Type == "" || req.PromptName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: server_id, type, prompt_name", nil)
		return
	}

	// Validate type
	if req.Type != "servers" && req.Type != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	// Create database record
	record := &database.BlockedPromptRecord{
		ServerID:   req.ServerID,
		Type:       req.Type,
		PromptName: req.PromptName,
	}

	created, err := h.db.CreateBlockedPrompt(record)
	if err != nil {
		h.writeErrorResponse(w, http.StatusConflict, "Failed to create blocked prompt", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusCreated, "Blocked prompt created successfully", created)

	// Invalidate cache after creating blocked prompt
	if h.invalidateCacheCallback != nil {
		h.invalidateCacheCallback()
	}

	// Audit log for blocked prompt creation
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.Audit(r.Context()).Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_prompt_created").
			Int64("server_id", created.ServerID).
			Str("server_type", created.Type).
			Str("prompt_name", created.PromptName).
			Int64("blocked_prompt_id", created.ID).
			Msg("Admin created new blocked prompt")
	}
}

// GetBlockedPrompt handles GET /api/blocked-prompts/{id}
func (h *BlockedPromptHandler) GetBlockedPrompt(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing blocked prompt ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid blocked prompt ID", err)
		return
	}

	blockedPrompt, err := h.db.GetBlockedPrompt(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Blocked prompt not found", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked prompt retrieved successfully", blockedPrompt)
}

// ListBlockedPrompts handles GET /api/blocked-prompts
func (h *BlockedPromptHandler) ListBlockedPrompts(w http.ResponseWriter, r *http.Request) {
	// Check for query parameters to filter by server
	serverIDStr := r.URL.Query().Get("server_id")
	serverType := r.URL.Query().Get("type")

	if serverIDStr != "" && serverType != "" {
		// List blocked prompts for specific server
		serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server ID", err)
			return
		}

		blockedPrompts, err := h.db.ListBlockedPromptsByServerID(serverID, serverType)
		if err != nil {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked prompts", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusOK, "Blocked prompts retrieved successfully", blockedPrompts)
		return
	}

	// List all blocked prompts
	blockedPrompts, err := h.db.ListAllBlockedPrompts()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked prompts", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked prompts retrieved successfully", blockedPrompts)
}

// ListBlockedPromptsByServer handles GET /api/blocked-prompts/server/{server_id}?type={type}
func (h *BlockedPromptHandler) ListBlockedPromptsByServer(w http.ResponseWriter, r *http.Request) {
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

	blockedPrompts, err := h.db.ListBlockedPromptsByServerID(serverID, serverType)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked prompts", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked prompts retrieved successfully", blockedPrompts)
}

// DeleteBlockedPrompt handles DELETE /api/blocked-prompts/{id}
func (h *BlockedPromptHandler) DeleteBlockedPrompt(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing blocked prompt ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid blocked prompt ID", err)
		return
	}

	// Get blocked prompt info for audit log before deletion
	blockedPrompt, err := h.db.GetBlockedPrompt(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Blocked prompt not found", err)
		return
	}

	err = h.db.DeleteBlockedPrompt(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete blocked prompt", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked prompt deleted successfully", nil)

	// Invalidate cache after deleting blocked prompt
	if h.invalidateCacheCallback != nil {
		h.invalidateCacheCallback()
	}

	// Audit log for blocked prompt deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.Audit(r.Context()).Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_prompt_deleted").
			Int64("server_id", blockedPrompt.ServerID).
			Str("server_type", blockedPrompt.Type).
			Str("prompt_name", blockedPrompt.PromptName).
			Int64("blocked_prompt_id", blockedPrompt.ID).
			Msg("Admin deleted blocked prompt")
	}
}

// DeleteBlockedPromptByDetails handles DELETE /api/blocked-prompts/server/{server_id}/prompt/{prompt_name}?type={type}
func (h *BlockedPromptHandler) DeleteBlockedPromptByDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverIDStr, exists := vars["server_id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	promptName, exists := vars["prompt_name"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing prompt name", nil)
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

	err = h.db.DeleteBlockedPromptByDetails(serverID, serverType, promptName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Failed to delete blocked prompt", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked prompt deleted successfully", nil)

	// Invalidate cache after deleting blocked prompt
	if h.invalidateCacheCallback != nil {
		h.invalidateCacheCallback()
	}

	// Audit log for blocked prompt deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.Audit(r.Context()).Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_prompt_deleted").
			Int64("server_id", serverID).
			Str("server_type", serverType).
			Str("prompt_name", promptName).
			Msg("Admin deleted blocked prompt by details")
	}
}

// ToggleBlockedPrompt handles POST /api/blocked-prompts/toggle
func (h *BlockedPromptHandler) ToggleBlockedPrompt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID   int64  `json:"server_id" binding:"required"`
		Type       string `json:"type" binding:"required"` // "servers" or "curated_servers"
		PromptName string `json:"prompt_name" binding:"required"`
		Block      bool   `json:"block"` // true to block, false to unblock
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.ServerID == 0 || req.Type == "" || req.PromptName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: server_id, type, prompt_name", nil)
		return
	}

	// Validate type
	if req.Type != "servers" && req.Type != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	if req.Block {
		// Block the prompt
		record := &database.BlockedPromptRecord{
			ServerID:   req.ServerID,
			Type:       req.Type,
			PromptName: req.PromptName,
		}

		created, err := h.db.CreateBlockedPrompt(record)
		if err != nil {
			// If it's already blocked, that's okay
			if strings.Contains(err.Error(), "already blocked") {
				h.writeSuccessResponse(w, http.StatusOK, "Prompt is already blocked", nil)
				return
			}
			h.writeErrorResponse(w, http.StatusConflict, "Failed to block prompt", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusCreated, "Prompt blocked successfully", created)

		// Invalidate cache after blocking prompt
		if h.invalidateCacheCallback != nil {
			h.invalidateCacheCallback()
		}

		// Audit log for blocking
		if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
			logger.Audit(r.Context()).Info().
				Str("admin_username", user.Username).
				Str("action", "prompt_blocked").
				Int64("server_id", created.ServerID).
				Str("server_type", created.Type).
				Str("prompt_name", created.PromptName).
				Msg("Admin blocked prompt")
		}
	} else {
		// Unblock the prompt
		err := h.db.DeleteBlockedPromptByDetails(req.ServerID, req.Type, req.PromptName)
		if err != nil {
			// If it's not blocked, that's okay
			if strings.Contains(err.Error(), "not found") {
				h.writeSuccessResponse(w, http.StatusOK, "Prompt is not blocked", nil)
				return
			}
			h.writeErrorResponse(w, http.StatusNotFound, "Failed to unblock prompt", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusOK, "Prompt unblocked successfully", nil)

		// Invalidate cache after unblocking prompt
		if h.invalidateCacheCallback != nil {
			h.invalidateCacheCallback()
		}

		// Audit log for unblocking
		if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
			logger.Audit(r.Context()).Info().
				Str("admin_username", user.Username).
				Str("action", "prompt_unblocked").
				Int64("server_id", req.ServerID).
				Str("server_type", req.Type).
				Str("prompt_name", req.PromptName).
				Msg("Admin unblocked prompt")
		}
	}
}

// RegisterAdminRoutes registers admin-only blocked prompt routes
func (h *BlockedPromptHandler) RegisterAdminRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()

	// Admin-only blocked prompts CRUD
	api.HandleFunc("/blocked-prompts", h.CreateBlockedPrompt).Methods("POST")
	api.HandleFunc("/blocked-prompts", h.ListBlockedPrompts).Methods("GET")
	api.HandleFunc("/blocked-prompts/{id:[0-9]+}", h.GetBlockedPrompt).Methods("GET")
	api.HandleFunc("/blocked-prompts/{id:[0-9]+}", h.DeleteBlockedPrompt).Methods("DELETE")

	// Toggle endpoint for blocking/unblocking prompts
	api.HandleFunc("/blocked-prompts/toggle", h.ToggleBlockedPrompt).Methods("POST")

	// Additional convenience endpoints
	api.HandleFunc("/blocked-prompts/server/{server_id:[0-9]+}", h.ListBlockedPromptsByServer).Methods("GET")
	api.HandleFunc("/blocked-prompts/server/{server_id:[0-9]+}/prompt/{prompt_name}", h.DeleteBlockedPromptByDetails).Methods("DELETE")
}

// Helper methods
func (h *BlockedPromptHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *BlockedPromptHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
