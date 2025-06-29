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
	UIChangePasswordPath = "/ui/change-password"
	
	// API paths
	MCPPath         = "/mcp"
	MCPHTTPPath     = "/mcp/http"
	GatewayPath     = "/gateway"
	StatusPath      = "/gateway/status"
	UpstreamPath    = "/gateway/upstream"
	StatsPath       = "/gateway/stats"
	RefreshPath     = "/gateway/refresh"
	CurationPath    = "/gateway/curated-servers"
	HealthPath      = "/health"
	InfoPath        = "/info"
	LogsPath        = "/api/logs/{filename}"
	
	// File paths
	WebDir           = "web/"
	LoginHTMLFile    = "web/login.html"
	ChangePassHTMLFile = "web/change-password.html"
	
	// Token constants
	TokenCookieName  = "mcp_token"
	BearerPrefix     = "Bearer "
)

// Server represents the MCP gateway server
type Server struct {
	config         *config.Config
	db             *database.DB
	upgrader       websocket.Upgrader
	tools          map[string]*types.Tool
	resources      map[string]*types.Resource
	clients        map[string]*client.MCPClient
	prompts        map[string]*types.Prompt  // Store prompts from upstream servers (but don't expose locally)
	clientsByID    map[int64]*client.MCPClient
	mu             sync.RWMutex
	stats          types.GatewayStats
	upstreamHandler *handlers.UpstreamHandler
	curatedHandler  *handlers.CuratedServerHandler
	authHandler     *handlers.AuthHandler
	logger         zerolog.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	startTime      time.Time
}

// Start initializes and starts the MCP gateway server
func (s *Server) Start() error {
	s.logger.Info().Msg("Starting MCP Gateway Server...")
	
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
	}
	
	// Create upstream handler with server reference
	server.upstreamHandler = handlers.NewUpstreamHandler(db, server)
	
	// Create curated server handler
	server.curatedHandler = handlers.NewCuratedServerHandler(db)
	
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
}

// registerCommonRoutes registers routes available to all users
func (s *Server) registerCommonRoutes(r *mux.Router) {
	// Web UI routes
	r.HandleFunc(UIPath, s.handleUI).Methods("GET")
	r.HandleFunc(UILoginPath, s.handleLoginPage).Methods("GET")
	r.HandleFunc(UIChangePasswordPath, s.handleChangePasswordPage).Methods("GET")
	r.HandleFunc(UIAdminPath, s.handleAdminPage).Methods("GET")
	r.HandleFunc(UIUserPath, s.handleUserPage).Methods("GET")
	
	// API health/info routes
	r.HandleFunc(HealthPath, s.handleHealth).Methods("GET")
	r.HandleFunc(InfoPath, s.handleInfo).Methods("GET")
	
	// Static file serving for CSS, JS, and HTML files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(WebDir))))
	
	// Register public read-only curated server routes for all users
	s.curatedHandler.RegisterPublicRoutes(r)
}

// handleUI handles requests to the /ui path - redirects to appropriate page
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check if user is authenticated
		if s.isAuthenticated(r) {
			// Authenticated - check if user is admin
			if s.isUserAdmin(r) {
				// Admin user - redirect to admin panel
				http.Redirect(w, r, UIAdminPath, http.StatusFound)
			} else {
				// Regular user - redirect to user page
				http.Redirect(w, r, UIUserPath, http.StatusFound)
			}
		} else {
			// Not authenticated - redirect to login
			http.Redirect(w, r, UILoginPath, http.StatusFound)
		}
	} else {
		// No auth required - go straight to admin
		http.Redirect(w, r, UIAdminPath, http.StatusFound)
	}
}

// handleLoginPage serves the login page
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
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
		// Serve standalone login page
		s.serveHTMLWithAuth(w, LoginHTMLFile)
	} else {
		// Auth disabled - redirect to admin
		http.Redirect(w, r, UIAdminPath, http.StatusFound)
	}
}

// handleChangePasswordPage serves the change password page
func (s *Server) handleChangePasswordPage(w http.ResponseWriter, r *http.Request) {
	if !s.config.Security.EnableAuth {
		// Auth disabled - redirect to admin
		http.Redirect(w, r, UIAdminPath, http.StatusFound)
		return
	}

	// Check authentication
	if !s.isAuthenticated(r) {
		// Not authenticated - redirect to login
		http.Redirect(w, r, UILoginPath, http.StatusFound)
		return
	}

	// Serve change password page with auth status injected
	s.serveHTMLWithAuth(w, ChangePassHTMLFile)
}

// handleAdminPage serves the admin panel (protected route for admins only)
func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check authentication
		if !s.isAuthenticated(r) {
			// Not authenticated - redirect to login
			http.Redirect(w, r, UILoginPath, http.StatusFound)
			return
		}
		
		// Check if user is admin
		if !s.isUserAdmin(r) {
			// Authenticated but not admin - redirect to user page
			http.Redirect(w, r, UIUserPath, http.StatusFound)
			return
		}
	}
	
	// Serve admin panel with auth status injected
	s.serveHTMLWithAuth(w, "web/admin.html")
}

// handleUserPage serves the user page (protected route for authenticated users)
func (s *Server) handleUserPage(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check authentication
		if !s.isAuthenticated(r) {
			// Not authenticated - redirect to login
			http.Redirect(w, r, UILoginPath, http.StatusFound)
			return
		}
	}
	
	// Serve user page with auth status injected
	s.serveHTMLWithAuth(w, "web/user.html")
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
