package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/nadav-yo/mcp-gateway/internal/client"
	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/handlers"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
	"github.com/rs/zerolog"
)

// URL path constants
const (
	// UI paths
	UIPath               = "/ui"
	UIAdminPath          = "/ui/admin"
	UILoginPath          = "/ui/login"
	UIUserPath           = "/ui/user"

	// API paths
	MCPPath      = "/mcp"
	MCPHTTPPath  = "/mcp/http"
	GatewayPath  = "/gateway"
	StatusPath   = "/gateway/status"
	UpstreamPath = "/gateway/upstream"
	StatsPath    = "/gateway/stats"
	RefreshPath  = "/gateway/refresh"
	CurationPath = "/gateway/curated-servers"
	HealthPath   = "/health"
	InfoPath     = "/info"
	LogsPath     = "/api/logs/{filename}"

	// File paths
	ReactUIDir         = "ui-react/build/"

	// Token constants
	TokenCookieName = "mcp_token"
	BearerPrefix    = "Bearer "
)

// Server represents the MCP gateway server
type Server struct {
	config                  *config.Config
	db                      *database.DB
	upgrader                websocket.Upgrader
	tools                   map[string]*types.Tool
	resources               map[string]*types.Resource
	clients                 map[string]*client.MCPClient
	prompts                 map[string]*types.Prompt // Store prompts from upstream servers (but don't expose locally)
	clientsByID             map[int64]*client.MCPClient
	mu                      sync.RWMutex
	stats                   types.GatewayStats
	upstreamHandler         *handlers.UpstreamHandler
	curatedHandler          *handlers.CuratedServerHandler
	blockedToolsHandler     *handlers.BlockedToolHandler
	blockedPromptsHandler   *handlers.BlockedPromptHandler
	blockedResourcesHandler *handlers.BlockedResourceHandler
	authHandler             *handlers.AuthHandler
	logger                  zerolog.Logger
	ctx                     context.Context
	cancel                  context.CancelFunc
	startTime               time.Time

	// Cache for blocked tools to reduce database hits
	blockedToolsCache       map[string]bool // toolName -> isBlocked
	blockedToolsCacheMu     sync.RWMutex
	blockedToolsCacheExpiry time.Time

	// Cache for blocked prompts to reduce database hits
	blockedPromptsCache       map[string]bool // promptName -> isBlocked
	blockedPromptsCacheMu     sync.RWMutex
	blockedPromptsCacheExpiry time.Time

	// Cache for blocked resources to reduce database hits
	blockedResourcesCache       map[string]bool // resourceName -> isBlocked
	blockedResourcesCacheMu     sync.RWMutex
	blockedResourcesCacheExpiry time.Time
}

// Start initializes and starts the MCP gateway server
func (s *Server) Start() error {
	s.logger.Info().Msg("Initializing MCP Gateway Server...")

	// Connect to upstream servers at startup
	s.connectToUpstreamServers()

	s.logger.Info().Int("upstream_count", len(s.clients)).Msg("MCP Gateway Server started")
	return nil
}

// Shutdown gracefully shuts down the MCP gateway server
func (s *Server) Shutdown() error {
	s.logger.Info().Msg("Shutting down MCP Gateway Server...")

	// Cancel the server context to signal shutdown to all goroutines
	s.cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close all upstream connections
	for name, mcpClient := range s.clients {
		if err := mcpClient.Close(); err != nil {
			s.logger.Error().
				Err(err).
				Str("upstream", name).
				Msg("Error closing connection to upstream")
		}
	}

	s.logger.Info().Msg("MCP Gateway Server shutdown complete")
	return nil
}

// New creates a new MCP gateway server instance
func New(cfg *config.Config, db *database.DB) *Server {
	authHandler := handlers.NewAuthHandler(db)
	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		config: cfg,
		db:     db,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
		},
		tools:       make(map[string]*types.Tool),
		resources:   make(map[string]*types.Resource),
		prompts:     make(map[string]*types.Prompt),
		clients:     make(map[string]*client.MCPClient),
		clientsByID: make(map[int64]*client.MCPClient),
		authHandler: authHandler,
		logger:      logger.GetLogger("server"),
		ctx:         ctx,
		cancel:      cancel,
		startTime:   time.Now(),

		// Initialize blocked caches
		blockedToolsCache:     make(map[string]bool),
		blockedPromptsCache:   make(map[string]bool),
		blockedResourcesCache: make(map[string]bool),
	}

	// Create upstream handler with server reference
	server.upstreamHandler = handlers.NewUpstreamHandler(db, server)

	// Create curated server handler
	server.curatedHandler = handlers.NewCuratedServerHandler(db)

	// Create blocked tools handler with cache invalidation callback
	server.blockedToolsHandler = handlers.NewBlockedToolHandlerWithCallback(db, server.invalidateBlockedToolsCache)

	// Create blocked prompts handler with cache invalidation callback
	server.blockedPromptsHandler = handlers.NewBlockedPromptHandlerWithCallback(db, server.invalidateBlockedPromptsCache)

	// Create blocked resources handler with cache invalidation callback
	server.blockedResourcesHandler = handlers.NewBlockedResourceHandlerWithCallback(db, server.invalidateBlockedResourcesCache)

	return server
}

// Router returns the HTTP router
func (s *Server) Router() http.Handler {
	r := mux.NewRouter()

	// Add request logging middleware to all routes
	requestLogger := logger.NewRequestLoggerWithConfig(&s.config.Logging.Rotation)
	r.Use(requestLogger.Middleware)

	// Register authentication routes first (includes public login endpoint)
	s.authHandler.RegisterRoutes(r)

	// Configure routes based on authentication settings
	if s.config.Security.EnableAuth {
		s.setupAuthenticatedRoutes(r)
	} else {
		s.setupUnauthenticatedRoutes(r)
	}

	// Register common routes
	s.registerCommonRoutes(r)

	return r
}

// setupAuthenticatedRoutes configures routes when authentication is enabled
func (s *Server) setupAuthenticatedRoutes(r *mux.Router) {
	// Protected MCP endpoints
	mcpRouter := r.NewRoute().Subrouter()
	mcpRouter.Use(s.authHandler.AuthMiddleware)
	s.registerMCPRoutes(mcpRouter)
	s.registerGeneralGatewayRoutes(mcpRouter)

	// Public curated servers endpoints (read-only, available to all authenticated users)
	authenticatedRouter := r.NewRoute().Subrouter()
	authenticatedRouter.Use(s.authHandler.AuthMiddleware)
	s.curatedHandler.RegisterPublicRoutes(authenticatedRouter)

	// Admin-only endpoints
	adminRouter := r.NewRoute().Subrouter()
	adminRouter.Use(s.authHandler.AdminMiddleware)
	s.registerAdminRoutes(adminRouter)

	// Register admin user management routes
	s.authHandler.RegisterAdminRoutes(r)
}

// setupUnauthenticatedRoutes configures routes when authentication is disabled
func (s *Server) setupUnauthenticatedRoutes(r *mux.Router) {
	// All endpoints are unprotected
	s.registerMCPRoutes(r)
	s.registerGeneralGatewayRoutes(r)
	s.registerAdminRoutes(r)

	// Register public curated servers routes (when auth is disabled, all routes are public)
	s.curatedHandler.RegisterPublicRoutes(r)

	// Register admin user management routes (no auth when disabled)
	s.authHandler.RegisterAdminRoutes(r)

	// Register blocked tools routes (no auth when disabled)
	s.blockedToolsHandler.RegisterAdminRoutes(r)
	s.blockedPromptsHandler.RegisterAdminRoutes(r)
	s.blockedResourcesHandler.RegisterAdminRoutes(r)
}

// registerMCPRoutes registers MCP communication endpoints
func (s *Server) registerMCPRoutes(router *mux.Router) {
	// SSE endpoint for MCP communication (VS Code uses this)
	router.HandleFunc("/", s.handleSSE).Methods("GET", "POST")

	// WebSocket endpoint for MCP communication
	router.HandleFunc(MCPPath, s.handleWebSocket)

	// HTTP endpoints for MCP over HTTP
	router.HandleFunc(MCPHTTPPath, s.handleHTTP).Methods("POST")
}

// registerGeneralGatewayRoutes registers general gateway endpoints
func (s *Server) registerGeneralGatewayRoutes(router *mux.Router) {
	router.HandleFunc(StatusPath, s.handleGatewayStatus).Methods("GET")
	router.HandleFunc(StatsPath, s.handleGatewayStats).Methods("GET")
	router.HandleFunc(CurationPath, s.handleCuratedServers).Methods("GET")
}

// registerAdminRoutes registers admin-only endpoints
func (s *Server) registerAdminRoutes(router *mux.Router) {
	// Admin gateway endpoints
	router.HandleFunc(UpstreamPath, s.handleUpstreamServers).Methods("GET")
	router.HandleFunc(RefreshPath, s.handleRefreshConnections).Methods("POST")

	// Log endpoints
	router.HandleFunc(LogsPath, s.handleGenericLog).Methods("GET")

	// Register CRUD API routes
	s.upstreamHandler.RegisterRoutes(router)
	s.curatedHandler.RegisterAdminRoutes(router)
	s.blockedToolsHandler.RegisterAdminRoutes(router)
	s.blockedPromptsHandler.RegisterAdminRoutes(router)
	s.blockedResourcesHandler.RegisterAdminRoutes(router)
}

// registerCommonRoutes registers routes available to all users
func (s *Server) registerCommonRoutes(r *mux.Router) {


	// React UI routes
	r.HandleFunc(UILoginPath, s.handleReactLogin).Methods("GET")
	r.HandleFunc(UIAdminPath, s.handleReactAdmin).Methods("GET")
	r.HandleFunc(UIUserPath, s.handleReactUser).Methods("GET")
	r.PathPrefix(UIPath).HandlerFunc(s.handleReactUI).Methods("GET")

	// API health/info routes
	r.HandleFunc(HealthPath, s.handleHealth).Methods("GET")
	r.HandleFunc(InfoPath, s.handleInfo).Methods("GET")

	// Register public read-only curated server routes for all users
	s.curatedHandler.RegisterPublicRoutes(r)
}

// handleReactUI handles requests to the /ui path - serves React UI with routing
func (s *Server) handleReactUI(w http.ResponseWriter, r *http.Request) {
	// Remove the /ui prefix to get the React route
	path := strings.TrimPrefix(r.URL.Path, UIPath)
	if path == "" || path == "/" {
		path = "/index.html"
	}

	// Static assets (CSS, JS, images, etc.) should not require authentication
	isStaticAsset := strings.Contains(path, ".") && (strings.HasPrefix(path, "/static/") ||
		strings.HasSuffix(path, ".css") ||
		strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".map") ||
		strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".svg") ||
		strings.HasSuffix(path, ".woff") ||
		strings.HasSuffix(path, ".woff2") ||
		strings.HasSuffix(path, ".ttf") ||
		strings.HasSuffix(path, ".eot"))

	// For React Router, serve index.html for non-static routes
	if !strings.Contains(path, ".") {
		path = "/index.html"
	}

	// Try to serve the file from the React build directory
	filePath := ReactUIDir + strings.TrimPrefix(path, "/")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// File doesn't exist, serve index.html (for React Router)
		filePath = ReactUIDir + "index.html"
	}

	// Check authentication only for non-static assets
	if !isStaticAsset && s.config.Security.EnableAuth && !s.isAuthenticated(r) {
		// Not authenticated - redirect to React login
		http.Redirect(w, r, UILoginPath, http.StatusFound)
		return
	}

	// Set appropriate content type for static assets
	if isStaticAsset {
		if strings.HasSuffix(path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else if strings.HasSuffix(path, ".json") {
			w.Header().Set("Content-Type", "application/json")
		} else if strings.HasSuffix(path, ".svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		}
	}
	
	// Also set content type for manifest.json and other JSON files even if not in static assets check
	if strings.HasSuffix(path, ".json") {
		w.Header().Set("Content-Type", "application/json")
	}

	// Serve the file
	http.ServeFile(w, r, filePath)
}

// handleReactLogin handles requests to the React login page
func (s *Server) handleReactLogin(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check if already authenticated
		if s.isAuthenticated(r) {
			// Already logged in - redirect to appropriate page based on role
			if s.isUserAdmin(r) {
				http.Redirect(w, r, UIAdminPath, http.StatusFound)
			} else {
				http.Redirect(w, r, UIUserPath, http.StatusFound)
			}
			return
		}
	} else {
		// Auth disabled - redirect to React admin
		http.Redirect(w, r, UIAdminPath, http.StatusFound)
		return
	}

	// Serve React app index.html
	http.ServeFile(w, r, ReactUIDir+"index.html")
}

// handleReactAdmin handles requests to the React admin page
func (s *Server) handleReactAdmin(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check authentication
		if !s.isAuthenticated(r) {
			// Not authenticated - redirect to React login
			http.Redirect(w, r, UILoginPath, http.StatusFound)
			return
		}

		// Check if user is admin
		if !s.isUserAdmin(r) {
			// Authenticated but not admin - redirect to React user page
			http.Redirect(w, r, UIUserPath, http.StatusFound)
			return
		}
	}

	// Serve React app index.html
	http.ServeFile(w, r, ReactUIDir+"index.html")
}

// handleReactUser handles requests to the React user page
func (s *Server) handleReactUser(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check authentication
		if !s.isAuthenticated(r) {
			// Not authenticated - redirect to React login
			http.Redirect(w, r, UILoginPath, http.StatusFound)
			return
		}
	}

	// Serve React app index.html
	http.ServeFile(w, r, ReactUIDir+"index.html")
}

// extractToken extracts the authentication token from the request
func (s *Server) extractToken(r *http.Request) string {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, BearerPrefix) {
		return strings.TrimPrefix(authHeader, BearerPrefix)
	}

	// Try cookie
	if cookie, err := r.Cookie(TokenCookieName); err == nil {
		return cookie.Value
	}

	return ""
}

// isAuthenticated checks if the request has valid authentication
func (s *Server) isAuthenticated(r *http.Request) bool {
	token := s.extractToken(r)
	if token == "" {
		return false
	}

	// Validate token
	_, err := s.db.ValidateToken(token)
	return err == nil
}

// isUserAdmin checks if the authenticated user has admin privileges
func (s *Server) isUserAdmin(r *http.Request) bool {
	token := s.extractToken(r)
	if token == "" {
		return false
	}

	// Validate token and get token record
	tokenRecord, err := s.db.ValidateToken(token)
	if err != nil {
		return false
	}

	// Get user details to check admin status
	user, err := s.db.GetUser(tokenRecord.UserID)
	if err != nil {
		return false
	}

	return user.IsAdmin
}

// isToolBlocked checks if a tool is blocked for any of the servers that provide it
// Uses caching to reduce database hits
func (s *Server) isToolBlocked(toolName string) bool {
	// Check cache first
	s.blockedToolsCacheMu.RLock()
	if time.Now().Before(s.blockedToolsCacheExpiry) {
		if blocked, exists := s.blockedToolsCache[toolName]; exists {
			s.blockedToolsCacheMu.RUnlock()
			return blocked
		}
	}
	s.blockedToolsCacheMu.RUnlock()

	// Cache miss or expired - rebuild cache
	s.refreshBlockedToolsCache()

	// Check cache again
	s.blockedToolsCacheMu.RLock()
	blocked := s.blockedToolsCache[toolName]
	s.blockedToolsCacheMu.RUnlock()

	return blocked
}

// isPromptBlocked checks if a prompt is blocked for any of the servers that provide it
// Uses caching to reduce database hits
func (s *Server) isPromptBlocked(promptName string) bool {
	// Check cache first
	s.blockedPromptsCacheMu.RLock()
	if time.Now().Before(s.blockedPromptsCacheExpiry) {
		if blocked, exists := s.blockedPromptsCache[promptName]; exists {
			s.blockedPromptsCacheMu.RUnlock()
			return blocked
		}
	}
	s.blockedPromptsCacheMu.RUnlock()

	// Cache miss or expired - rebuild cache
	s.refreshBlockedPromptsCache()

	// Check cache again
	s.blockedPromptsCacheMu.RLock()
	blocked := s.blockedPromptsCache[promptName]
	s.blockedPromptsCacheMu.RUnlock()

	return blocked
}

// isResourceBlocked checks if a resource is blocked for any of the servers that provide it
// Uses caching to reduce database hits
func (s *Server) isResourceBlocked(resourceName string) bool {
	// Check cache first
	s.blockedResourcesCacheMu.RLock()
	if time.Now().Before(s.blockedResourcesCacheExpiry) {
		if blocked, exists := s.blockedResourcesCache[resourceName]; exists {
			s.blockedResourcesCacheMu.RUnlock()
			return blocked
		}
	}
	s.blockedResourcesCacheMu.RUnlock()

	// Cache miss or expired - rebuild cache
	s.refreshBlockedResourcesCache()

	// Check cache again
	s.blockedResourcesCacheMu.RLock()
	blocked := s.blockedResourcesCache[resourceName]
	s.blockedResourcesCacheMu.RUnlock()

	return blocked
}

// refreshBlockedToolsCache rebuilds the blocked tools cache
// DEADLOCK FIX: This function now copies data from the server mutex before doing database operations
// to prevent deadlocks when cache refresh happens during server disconnect/connect operations
func (s *Server) refreshBlockedToolsCache() {
	s.blockedToolsCacheMu.Lock()
	defer s.blockedToolsCacheMu.Unlock()

	// Don't rebuild if recently refreshed by another goroutine
	if time.Now().Before(s.blockedToolsCacheExpiry) {
		return
	}

	s.logger.Debug().Msg("Refreshing blocked tools cache")

	// Clear existing cache
	s.blockedToolsCache = make(map[string]bool)

	// Get all tools and their providing servers - copy data to avoid holding lock during DB operations
	var toolServerMap map[string][]int64
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()

		toolServerMap = make(map[string][]int64) // toolName -> []serverID
		for serverID, mcpClient := range s.clientsByID {
			if mcpClient.IsConnected() {
				clientTools := mcpClient.GetTools()
				for toolName := range clientTools {
					toolServerMap[toolName] = append(toolServerMap[toolName], serverID)
				}
			}
		}
	}()

	// Batch check blocked status for all tools - do this outside of any mutex locks
	for toolName, serverIDs := range toolServerMap {
		isBlocked := false
		for _, serverID := range serverIDs {
			blocked, err := s.db.IsToolBlocked(serverID, "servers", toolName)
			if err != nil {
				s.logger.Error().Err(err).Int64("server_id", serverID).Str("tool_name", toolName).Msg("Error checking if tool is blocked")
				continue
			}
			if blocked {
				isBlocked = true
				break // If blocked on any server, tool is blocked
			}
		}
		s.blockedToolsCache[toolName] = isBlocked
	}

	// Set cache expiry (5 minutes)
	s.blockedToolsCacheExpiry = time.Now().Add(5 * time.Minute)

	s.logger.Debug().Int("cached_tools", len(s.blockedToolsCache)).Msg("Blocked tools cache refreshed")
}

// refreshBlockedPromptsCache rebuilds the blocked prompts cache
func (s *Server) refreshBlockedPromptsCache() {
	s.blockedPromptsCacheMu.Lock()
	defer s.blockedPromptsCacheMu.Unlock()

	// Don't rebuild if recently refreshed by another goroutine
	if time.Now().Before(s.blockedPromptsCacheExpiry) {
		return
	}

	s.logger.Debug().Msg("Refreshing blocked prompts cache")

	// Clear existing cache
	s.blockedPromptsCache = make(map[string]bool)

	// Get all prompts and their providing servers - copy data to avoid holding lock during DB operations
	var promptServerMap map[string][]int64
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()

		promptServerMap = make(map[string][]int64) // promptName -> []serverID
		for serverID, mcpClient := range s.clientsByID {
			if mcpClient.IsConnected() {
				clientPrompts := mcpClient.GetPrompts()
				for promptName := range clientPrompts {
					promptServerMap[promptName] = append(promptServerMap[promptName], serverID)
				}
			}
		}
	}()

	// Batch check blocked status for all prompts - do this outside of any mutex locks
	for promptName, serverIDs := range promptServerMap {
		isBlocked := false
		for _, serverID := range serverIDs {
			blocked, err := s.db.IsPromptBlocked(serverID, "servers", promptName)
			if err != nil {
				s.logger.Error().Err(err).Int64("server_id", serverID).Str("prompt_name", promptName).Msg("Error checking if prompt is blocked")
				continue
			}
			if blocked {
				isBlocked = true
				break // If blocked on any server, prompt is blocked
			}
		}
		s.blockedPromptsCache[promptName] = isBlocked
	}

	// Set cache expiry (5 minutes)
	s.blockedPromptsCacheExpiry = time.Now().Add(5 * time.Minute)

	s.logger.Debug().Int("cached_prompts", len(s.blockedPromptsCache)).Msg("Blocked prompts cache refreshed")
}

// refreshBlockedResourcesCache rebuilds the blocked resources cache
func (s *Server) refreshBlockedResourcesCache() {
	s.blockedResourcesCacheMu.Lock()
	defer s.blockedResourcesCacheMu.Unlock()

	// Don't rebuild if recently refreshed by another goroutine
	if time.Now().Before(s.blockedResourcesCacheExpiry) {
		return
	}

	s.logger.Debug().Msg("Refreshing blocked resources cache")

	// Clear existing cache
	s.blockedResourcesCache = make(map[string]bool)

	// Get all resources and their providing servers - copy data to avoid holding lock during DB operations
	var resourceServerMap map[string][]int64
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()

		resourceServerMap = make(map[string][]int64) // resourceName -> []serverID
		for serverID, mcpClient := range s.clientsByID {
			if mcpClient.IsConnected() {
				clientResources := mcpClient.GetResources()
				for resourceName := range clientResources {
					resourceServerMap[resourceName] = append(resourceServerMap[resourceName], serverID)
				}
			}
		}
	}()

	// Batch check blocked status for all resources - do this outside of any mutex locks
	for resourceName, serverIDs := range resourceServerMap {
		isBlocked := false
		for _, serverID := range serverIDs {
			blocked, err := s.db.IsResourceBlocked(serverID, "servers", resourceName)
			if err != nil {
				s.logger.Error().Err(err).Int64("server_id", serverID).Str("resource_name", resourceName).Msg("Error checking if resource is blocked")
				continue
			}
			if blocked {
				isBlocked = true
				break // If blocked on any server, resource is blocked
			}
		}
		s.blockedResourcesCache[resourceName] = isBlocked
	}

	// Set cache expiry (5 minutes)
	s.blockedResourcesCacheExpiry = time.Now().Add(5 * time.Minute)

	s.logger.Debug().Int("cached_resources", len(s.blockedResourcesCache)).Msg("Blocked resources cache refreshed")
}

// invalidateBlockedToolsCache forces a cache refresh on next access
func (s *Server) invalidateBlockedToolsCache() {
	s.blockedToolsCacheMu.Lock()
	s.blockedToolsCacheExpiry = time.Time{} // Set to zero time to force refresh
	s.blockedToolsCacheMu.Unlock()
	s.logger.Debug().Msg("Blocked tools cache invalidated")
}

// invalidateBlockedPromptsCache forces a cache refresh on next access
func (s *Server) invalidateBlockedPromptsCache() {
	s.blockedPromptsCacheMu.Lock()
	s.blockedPromptsCacheExpiry = time.Time{} // Set to zero time to force refresh
	s.blockedPromptsCacheMu.Unlock()
	s.logger.Debug().Msg("Blocked prompts cache invalidated")
}

// invalidateBlockedResourcesCache forces a cache refresh on next access
func (s *Server) invalidateBlockedResourcesCache() {
	s.blockedResourcesCacheMu.Lock()
	s.blockedResourcesCacheExpiry = time.Time{} // Set to zero time to force refresh
	s.blockedResourcesCacheMu.Unlock()
	s.logger.Debug().Msg("Blocked resources cache invalidated")
}

// serveHTMLWithAuth serves an HTML file with auth status injected
func (s *Server) serveHTMLWithAuth(w http.ResponseWriter, filePath string) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		s.logger.Error().Err(err).Str("file", filePath).Msg("Failed to read HTML file")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Inject auth status
	authEnabled := "false"
	if s.config.Security.EnableAuth {
		authEnabled = "true"
	}

	htmlContent := string(content)
	authScript := fmt.Sprintf(`    <script>window.AUTH_ENABLED = %s;</script>
</head>`, authEnabled)
	htmlContent = strings.Replace(htmlContent, "</head>", authScript, 1)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlContent))
}

// routePromptGet routes a prompt get request to the appropriate upstream server
func (s *Server) routePromptGet(prompt *types.Prompt, name string, arguments map[string]interface{}) types.GetPromptResponse {
	// Determine which upstream server this prompt belongs to
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if this is a prompt from an upstream server
	for clientName, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			clientPrompts := mcpClient.GetPrompts()
			if _, exists := clientPrompts[name]; exists {
				// Route to upstream server
				if result, err := mcpClient.GetPrompt(name, arguments); err == nil {
					return *result
				} else {
					s.logger.Error().
						Err(err).
						Str("prompt_name", name).
						Str("upstream", clientName).
						Msg("Error getting prompt from upstream")
					return types.GetPromptResponse{
						Description: fmt.Sprintf("Error getting prompt from upstream: %v", err),
						Messages:    []types.PromptMessage{},
					}
				}
			}
		}
	}

	// Prompt not found in any upstream server
	return types.GetPromptResponse{
		Description: fmt.Sprintf("Prompt '%s' not found in any upstream server", name),
		Messages:    []types.PromptMessage{},
	}
}
