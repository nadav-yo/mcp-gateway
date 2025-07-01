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

// BlockedToolHandler handles CRUD operations for blocked tools
type BlockedToolHandler struct {
	db     *database.DB
	logger zerolog.Logger
}

// NewBlockedToolHandler creates a new blocked tool handler
func NewBlockedToolHandler(db *database.DB) *BlockedToolHandler {
	return &BlockedToolHandler{
		db:     db,
		logger: logger.GetLogger("blocked-tool-handler"),
	}
}

// CreateBlockedToolRequest represents the request to create a blocked tool
type CreateBlockedToolRequest struct {
	ServerID int64  `json:"server_id" binding:"required"`
	Type     string `json:"type" binding:"required"` // "servers" or "curated_servers"
	ToolName string `json:"tool_name" binding:"required"`
}

// CreateBlockedTool handles POST /api/blocked-tools
func (h *BlockedToolHandler) CreateBlockedTool(w http.ResponseWriter, r *http.Request) {
	var req CreateBlockedToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.ServerID == 0 || req.Type == "" || req.ToolName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: server_id, type, tool_name", nil)
		return
	}

	// Validate type
	if req.Type != "servers" && req.Type != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	// Create database record
	record := &database.BlockedToolRecord{
		ServerID: req.ServerID,
		Type:     req.Type,
		ToolName: req.ToolName,
	}

	created, err := h.db.CreateBlockedTool(record)
	if err != nil {
		h.writeErrorResponse(w, http.StatusConflict, "Failed to create blocked tool", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusCreated, "Blocked tool created successfully", created)

	// Audit log for blocked tool creation
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_tool_created").
			Int64("server_id", created.ServerID).
			Str("server_type", created.Type).
			Str("tool_name", created.ToolName).
			Int64("blocked_tool_id", created.ID).
			Msg("Admin created new blocked tool")
	}
}

// GetBlockedTool handles GET /api/blocked-tools/{id}
func (h *BlockedToolHandler) GetBlockedTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing blocked tool ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid blocked tool ID", err)
		return
	}

	blockedTool, err := h.db.GetBlockedTool(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Blocked tool not found", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked tool retrieved successfully", blockedTool)
}

// ListBlockedTools handles GET /api/blocked-tools
func (h *BlockedToolHandler) ListBlockedTools(w http.ResponseWriter, r *http.Request) {
	// Check for query parameters to filter by server
	serverIDStr := r.URL.Query().Get("server_id")
	serverType := r.URL.Query().Get("type")

	if serverIDStr != "" && serverType != "" {
		// List blocked tools for specific server
		serverID, err := strconv.ParseInt(serverIDStr, 10, 64)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid server_id parameter", err)
			return
		}

		blockedTools, err := h.db.ListBlockedToolsByServerID(serverID, serverType)
		if err != nil {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked tools", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusOK, "Blocked tools retrieved successfully", blockedTools)
		return
	}

	// List all blocked tools
	blockedTools, err := h.db.ListAllBlockedTools()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked tools", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked tools retrieved successfully", blockedTools)
}

// ListBlockedToolsByServer handles GET /api/blocked-tools/server/{server_id}?type={type}
func (h *BlockedToolHandler) ListBlockedToolsByServer(w http.ResponseWriter, r *http.Request) {
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

	blockedTools, err := h.db.ListBlockedToolsByServerID(serverID, serverType)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list blocked tools", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked tools retrieved successfully", blockedTools)
}

// DeleteBlockedTool handles DELETE /api/blocked-tools/{id}
func (h *BlockedToolHandler) DeleteBlockedTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing blocked tool ID", nil)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid blocked tool ID", err)
		return
	}

	// Get blocked tool info for audit log before deletion
	blockedTool, err := h.db.GetBlockedTool(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Blocked tool not found", err)
		return
	}

	err = h.db.DeleteBlockedTool(id)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete blocked tool", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked tool deleted successfully", nil)

	// Audit log for blocked tool deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_tool_deleted").
			Int64("server_id", blockedTool.ServerID).
			Str("server_type", blockedTool.Type).
			Str("tool_name", blockedTool.ToolName).
			Int64("blocked_tool_id", blockedTool.ID).
			Msg("Admin deleted blocked tool")
	}
}

// DeleteBlockedToolByDetails handles DELETE /api/blocked-tools/server/{server_id}/tool/{tool_name}?type={type}
func (h *BlockedToolHandler) DeleteBlockedToolByDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serverIDStr, exists := vars["server_id"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing server ID", nil)
		return
	}

	toolName, exists := vars["tool_name"]
	if !exists {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing tool name", nil)
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

	err = h.db.DeleteBlockedToolByDetails(serverID, serverType, toolName)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Failed to delete blocked tool", err)
		return
	}

	h.writeSuccessResponse(w, http.StatusOK, "Blocked tool deleted successfully", nil)

	// Audit log for blocked tool deletion
	if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
		logger.GetAuditLogger().Info().
			Str("admin_username", user.Username).
			Str("action", "blocked_tool_deleted").
			Int64("server_id", serverID).
			Str("server_type", serverType).
			Str("tool_name", toolName).
			Msg("Admin deleted blocked tool by details")
	}
}

// ToggleBlockedTool handles POST /api/blocked-tools/toggle
func (h *BlockedToolHandler) ToggleBlockedTool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID int64  `json:"server_id" binding:"required"`
		Type     string `json:"type" binding:"required"` // "servers" or "curated_servers"
		ToolName string `json:"tool_name" binding:"required"`
		Block    bool   `json:"block"` // true to block, false to unblock
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Validate required fields
	if req.ServerID == 0 || req.Type == "" || req.ToolName == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Missing required fields: server_id, type, tool_name", nil)
		return
	}

	// Validate type
	if req.Type != "servers" && req.Type != "curated_servers" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid type. Must be 'servers' or 'curated_servers'", nil)
		return
	}

	if req.Block {
		// Block the tool
		record := &database.BlockedToolRecord{
			ServerID: req.ServerID,
			Type:     req.Type,
			ToolName: req.ToolName,
		}

		created, err := h.db.CreateBlockedTool(record)
		if err != nil {
			// If it's already blocked, that's okay
			if strings.Contains(err.Error(), "already blocked") {
				h.writeSuccessResponse(w, http.StatusOK, "Tool is already blocked", nil)
				return
			}
			h.writeErrorResponse(w, http.StatusConflict, "Failed to block tool", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusCreated, "Tool blocked successfully", created)

		// Audit log for blocking
		if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
			logger.GetAuditLogger().Info().
				Str("admin_username", user.Username).
				Str("action", "tool_blocked").
				Int64("server_id", created.ServerID).
				Str("server_type", created.Type).
				Str("tool_name", created.ToolName).
				Msg("Admin blocked tool")
		}
	} else {
		// Unblock the tool
		err := h.db.DeleteBlockedToolByDetails(req.ServerID, req.Type, req.ToolName)
		if err != nil {
			// If it's not blocked, that's okay
			if strings.Contains(err.Error(), "not found") {
				h.writeSuccessResponse(w, http.StatusOK, "Tool is not blocked", nil)
				return
			}
			h.writeErrorResponse(w, http.StatusNotFound, "Failed to unblock tool", err)
			return
		}

		h.writeSuccessResponse(w, http.StatusOK, "Tool unblocked successfully", nil)

		// Audit log for unblocking
		if user, ok := r.Context().Value("user").(*database.TokenRecord); ok {
			logger.GetAuditLogger().Info().
				Str("admin_username", user.Username).
				Str("action", "tool_unblocked").
				Int64("server_id", req.ServerID).
				Str("server_type", req.Type).
				Str("tool_name", req.ToolName).
				Msg("Admin unblocked tool")
		}
	}
}

// RegisterAdminRoutes registers admin-only blocked tool routes
func (h *BlockedToolHandler) RegisterAdminRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()

	// Admin-only blocked tools CRUD
	api.HandleFunc("/blocked-tools", h.CreateBlockedTool).Methods("POST")
	api.HandleFunc("/blocked-tools", h.ListBlockedTools).Methods("GET")
	api.HandleFunc("/blocked-tools/{id:[0-9]+}", h.GetBlockedTool).Methods("GET")
	api.HandleFunc("/blocked-tools/{id:[0-9]+}", h.DeleteBlockedTool).Methods("DELETE")

	// Toggle endpoint for blocking/unblocking tools
	api.HandleFunc("/blocked-tools/toggle", h.ToggleBlockedTool).Methods("POST")

	// Additional convenience endpoints
	api.HandleFunc("/blocked-tools/server/{server_id:[0-9]+}", h.ListBlockedToolsByServer).Methods("GET")
	api.HandleFunc("/blocked-tools/server/{server_id:[0-9]+}/tool/{tool_name}", h.DeleteBlockedToolByDetails).Methods("DELETE")
}

// Helper methods
func (h *BlockedToolHandler) writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *BlockedToolHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
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
