package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
