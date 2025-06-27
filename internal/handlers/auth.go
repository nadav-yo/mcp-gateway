package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/rs/zerolog"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	db     *database.DB
	logger zerolog.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(db *database.DB) *AuthHandler {
	return &AuthHandler{
		db:     db,
		logger: logger.GetLogger("auth"),
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	User      UserInfo  `json:"user"`
}

// UserInfo represents user information returned in responses
type UserInfo struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	IsActive bool   `json:"is_active"`
	IsAdmin  bool   `json:"is_admin"`
}

// CreateTokenRequest represents a request to create a new token
type CreateTokenRequest struct {
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	ID          int64      `json:"id"`
	Token       string     `json:"token"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	IsAdmin  bool   `json:"is_admin"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	IsActive *bool  `json:"is_active,omitempty"`
	IsAdmin  *bool  `json:"is_admin,omitempty"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	IsActive  bool      `json:"is_active"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// HandleLogin handles user login requests
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error().Err(err).Msg("Failed to decode login request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate user credentials
	user, err := h.db.ValidateUser(req.Username, req.Password)
	if err != nil {
		h.logger.Warn().Str("username", req.Username).Msg("Login attempt failed")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create a token with 24 hour expiration
	expiresAt := time.Now().Add(24 * time.Hour)
	token, err := h.db.CreateToken(user.ID, user.Username, "Login token", &expiresAt, true) // true = internal token
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to create token")
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token:     token.Token,
		ExpiresAt: token.ExpiresAt,
		User: UserInfo{
			ID:       user.ID,
			Username: user.Username,
			IsActive: user.IsActive,
			IsAdmin:  user.IsAdmin,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	h.logger.Info().Str("username", user.Username).Msg("User logged in successfully")
}

// HandleCreateToken handles requests to create new tokens
func (h *AuthHandler) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by auth middleware)
	user, ok := r.Context().Value("user").(*database.TokenRecord)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error().Err(err).Msg("Failed to decode create token request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.db.CreateToken(user.UserID, user.Username, req.Description, req.ExpiresAt, false) // false = not internal
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to create token")
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		ID:          token.ID,
		Token:       token.Token,
		Description: token.Description,
		ExpiresAt:   token.ExpiresAt,
		CreatedAt:   token.CreatedAt,
		LastUsed:    token.LastUsed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	h.logger.Info().Str("username", user.Username).Msg("Token created successfully")
}

// HandleListTokens handles requests to list user tokens
func (h *AuthHandler) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by auth middleware)
	user, ok := r.Context().Value("user").(*database.TokenRecord)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokens, err := h.db.ListTokens(user.UserID)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list tokens")
		http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
		return
	}

	var response []TokenResponse
	for _, token := range tokens {
		// Mask the token for security (show only first 8 characters)
		maskedToken := token.Token
		if len(maskedToken) > 8 {
			maskedToken = maskedToken[:8] + "..." + maskedToken[len(maskedToken)-4:]
		}

		response = append(response, TokenResponse{
			ID:          token.ID,
			Token:       maskedToken,
			Description: token.Description,
			ExpiresAt:   token.ExpiresAt,
			CreatedAt:   token.CreatedAt,
			LastUsed:    token.LastUsed,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleRevokeToken handles requests to revoke tokens
func (h *AuthHandler) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by auth middleware)
	user, ok := r.Context().Value("user").(*database.TokenRecord)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get token ID from URL path
	tokenID := r.URL.Query().Get("id")
	if tokenID == "" {
		http.Error(w, "Token ID required", http.StatusBadRequest)
		return
	}

	// Convert to int64
	var id int64
	if _, err := fmt.Sscanf(tokenID, "%d", &id); err != nil {
		http.Error(w, "Invalid token ID", http.StatusBadRequest)
		return
	}

	err := h.db.RevokeToken(id, user.UserID)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to revoke token")
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	h.logger.Info().Str("username", user.Username).Int64("token_id", id).Msg("Token revoked successfully")
}

// HandleCreateUser handles requests to create new users
func (h *AuthHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error().Err(err).Msg("Failed to decode create user request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Create the user
	user, err := h.db.CreateUserWithAdmin(req.Username, req.Password, req.IsAdmin)
	if err != nil {
		h.logger.Error().Err(err).Str("username", req.Username).Msg("Failed to create user")
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Username already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
		}
		return
	}

	response := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		IsActive:  user.IsActive,
		IsAdmin:   user.IsAdmin,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	h.logger.Info().Str("username", user.Username).Bool("is_admin", user.IsAdmin).Msg("User created successfully")
}

// HandleListUsers handles requests to list all users
func (h *AuthHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers()
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to list users")
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	var responses []UserResponse
	for _, user := range users {
		responses = append(responses, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			IsActive:  user.IsActive,
			IsAdmin:   user.IsAdmin,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responses)
}

// HandleGetUser handles requests to get a specific user
func (h *AuthHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUser(userID)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("Failed to get user")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		IsActive:  user.IsActive,
		IsAdmin:   user.IsAdmin,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleUpdateUser handles requests to update a user
func (h *AuthHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get the current user to prevent them from removing their own admin privileges
	currentUser, ok := r.Context().Value("user").(*database.TokenRecord)
	if !ok {
		http.Error(w, "User context not found", http.StatusInternalServerError)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error().Err(err).Msg("Failed to decode update user request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get the existing user
	existingUser, err := h.db.GetUser(userID)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("Failed to get user for update")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Prevent users from removing their own admin privileges
	if currentUser.UserID == userID && req.IsAdmin != nil && !*req.IsAdmin && existingUser.IsAdmin {
		http.Error(w, "Cannot remove your own admin privileges", http.StatusForbidden)
		return
	}

	// Use existing values if not provided in request
	username := existingUser.Username
	if req.Username != "" {
		username = req.Username
	}

	isActive := existingUser.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	isAdmin := existingUser.IsAdmin
	if req.IsAdmin != nil {
		isAdmin = *req.IsAdmin
	}

	password := ""
	if req.Password != "" {
		password = req.Password
	}

	// Update the user
	updatedUser, err := h.db.UpdateUser(userID, username, password, isActive, isAdmin)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("Failed to update user")
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Username already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
		}
		return
	}

	response := UserResponse{
		ID:        updatedUser.ID,
		Username:  updatedUser.Username,
		IsActive:  updatedUser.IsActive,
		IsAdmin:   updatedUser.IsAdmin,
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	h.logger.Info().
		Int64("user_id", userID).
		Str("username", updatedUser.Username).
		Bool("is_admin", updatedUser.IsAdmin).
		Msg("User updated successfully")
}

// HandleDeleteUser handles requests to delete a user
func (h *AuthHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get the current user to prevent them from deleting themselves
	currentUser, ok := r.Context().Value("user").(*database.TokenRecord)
	if !ok {
		http.Error(w, "User context not found", http.StatusInternalServerError)
		return
	}

	// Prevent users from deleting themselves
	if currentUser.UserID == userID {
		http.Error(w, "Cannot delete your own account", http.StatusForbidden)
		return
	}

	// Check if user exists and get their info for logging
	existingUser, err := h.db.GetUser(userID)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("User not found for deletion")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Delete the user
	err = h.db.DeleteUser(userID)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("Failed to delete user")
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	h.logger.Info().
		Int64("user_id", userID).
		Str("username", existingUser.Username).
		Msg("User deleted successfully")
}

// AuthMiddleware provides authentication middleware for HTTP requests
func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate token
		tokenRecord, err := h.db.ValidateToken(token)
		if err != nil {
			h.logger.Warn().Err(err).Str("token", token[:8]+"...").Msg("Token validation failed")
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add user info to request context
		ctx := context.WithValue(r.Context(), "user", tokenRecord)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware provides admin-only access middleware
func (h *AuthHandler) AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First check authentication
		h.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context (set by AuthMiddleware)
			tokenRecord, ok := r.Context().Value("user").(*database.TokenRecord)
			if !ok {
				http.Error(w, "User context not found", http.StatusInternalServerError)
				return
			}

			// Get user details to check admin status
			user, err := h.db.GetUser(tokenRecord.UserID)
			if err != nil {
				h.logger.Error().Err(err).Int64("user_id", tokenRecord.UserID).Msg("Failed to get user for admin check")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Check if user is admin
			if !user.IsAdmin {
				h.logger.Warn().
					Str("username", user.Username).
					Str("endpoint", r.URL.Path).
					Msg("Non-admin user attempted to access admin endpoint")
				http.Error(w, "Admin access required", http.StatusForbidden)
				return
			}

			// User is admin, proceed with the request
			next.ServeHTTP(w, r)
		})).ServeHTTP(w, r)
	})
}

// RegisterRoutes registers authentication routes
func (h *AuthHandler) RegisterRoutes(router *mux.Router) {
	// Public routes (no authentication required)
	router.HandleFunc("/auth/login", h.HandleLogin).Methods("POST")

	// Protected routes (authentication required)
	authRouter := router.PathPrefix("/auth").Subrouter()
	authRouter.Use(h.AuthMiddleware)
	authRouter.HandleFunc("/tokens", h.HandleCreateToken).Methods("POST")
	authRouter.HandleFunc("/tokens", h.HandleListTokens).Methods("GET")
	authRouter.HandleFunc("/tokens/revoke", h.HandleRevokeToken).Methods("DELETE")
}

// RegisterAdminRoutes registers admin-only user management routes
func (h *AuthHandler) RegisterAdminRoutes(router *mux.Router) {
	// User management routes (admin only)
	adminRouter := router.PathPrefix("/admin").Subrouter()
	adminRouter.Use(h.AdminMiddleware)
	adminRouter.HandleFunc("/users", h.HandleCreateUser).Methods("POST")
	adminRouter.HandleFunc("/users", h.HandleListUsers).Methods("GET")
	adminRouter.HandleFunc("/users/{id:[0-9]+}", h.HandleGetUser).Methods("GET")
	adminRouter.HandleFunc("/users/{id:[0-9]+}", h.HandleUpdateUser).Methods("PUT")
	adminRouter.HandleFunc("/users/{id:[0-9]+}", h.HandleDeleteUser).Methods("DELETE")
}
