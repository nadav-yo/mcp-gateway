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
	authHandler     *handlers.AuthHandler
	logger         zerolog.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	startTime      time.Time
}

	
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

	// Apply authentication middleware to MCP endpoints if auth is enabled
	if s.config.Security.EnableAuth {		
		// Protected MCP endpoints
		mcpRouter := r.NewRoute().Subrouter()
		mcpRouter.Use(s.authHandler.AuthMiddleware)
		
		// SSE endpoint for MCP communication (VS Code uses this)
		mcpRouter.HandleFunc("/", s.handleSSE).Methods("GET", "POST")
		
		// WebSocket endpoint for MCP communication
		mcpRouter.HandleFunc("/mcp", s.handleWebSocket)
		
		// HTTP endpoints for MCP over HTTP
		mcpRouter.HandleFunc("/mcp/http", s.handleHTTP).Methods("POST")
		
		// Gateway-specific endpoints (general access)
		mcpRouter.HandleFunc("/gateway/status", s.handleGatewayStatus).Methods("GET")
		mcpRouter.HandleFunc("/gateway/stats", s.handleGatewayStats).Methods("GET")
		
		// Admin-only endpoints
		adminRouter := r.NewRoute().Subrouter()
		adminRouter.Use(s.authHandler.AdminMiddleware)
		
		// Admin gateway endpoints
		adminRouter.HandleFunc("/gateway/upstream", s.handleUpstreamServers).Methods("GET")
		adminRouter.HandleFunc("/gateway/refresh", s.handleRefreshConnections).Methods("POST")
		
		// Log endpoints (admin only)
		adminRouter.HandleFunc("/api/logs/{filename}", s.handleGenericLog).Methods("GET")
		
		// Register CRUD API routes with admin access
		s.upstreamHandler.RegisterRoutes(adminRouter)
		
		// Register admin user management routes
		s.authHandler.RegisterAdminRoutes(r)
	} else {
		// Unprotected endpoints when auth is disabled
		// SSE endpoint for MCP communication (VS Code uses this)
		r.HandleFunc("/", s.handleSSE).Methods("GET", "POST")
		
		// WebSocket endpoint for MCP communication
		r.HandleFunc("/mcp", s.handleWebSocket)
		
		// HTTP endpoints for MCP over HTTP
		r.HandleFunc("/mcp/http", s.handleHTTP).Methods("POST")
		
		// Gateway-specific endpoints (all accessible when auth disabled)
		r.HandleFunc("/gateway/status", s.handleGatewayStatus).Methods("GET")
		r.HandleFunc("/gateway/upstream", s.handleUpstreamServers).Methods("GET")
		r.HandleFunc("/gateway/stats", s.handleGatewayStats).Methods("GET")
		r.HandleFunc("/gateway/refresh", s.handleRefreshConnections).Methods("POST")
		
		// Log endpoints
		r.HandleFunc("/api/logs/{filename}", s.handleGenericLog).Methods("GET")
		
		// Register CRUD API routes without auth
		s.upstreamHandler.RegisterRoutes(r)
		
		// Register admin user management routes (no auth when disabled)
		s.authHandler.RegisterAdminRoutes(r)
	}

	// Web UI routes
	r.HandleFunc("/ui", s.handleUI).Methods("GET")
	r.HandleFunc("/ui/login", s.handleLoginPage).Methods("GET")
	r.HandleFunc("/ui/change-password", s.handleChangePasswordPage).Methods("GET")
	r.HandleFunc("/ui/admin", s.handleAdminPage).Methods("GET")
	r.HandleFunc("/ui/user", s.handleUserPage).Methods("GET")
	
	// API health/info routes
	r.HandleFunc("/health", s.handleHealth).Methods("GET")
	r.HandleFunc("/info", s.handleInfo).Methods("GET")
	
	// Static file serving for CSS, JS, and HTML files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/"))))
	
	return r
}

// handleUI handles requests to the /ui path - redirects to appropriate page
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check if user is authenticated
		if s.isAuthenticated(r) {
			// Authenticated - check if user is admin
			if s.isUserAdmin(r) {
				// Admin user - redirect to admin panel
				http.Redirect(w, r, "/ui/admin", http.StatusFound)
			} else {
				// Regular user - redirect to user page
				http.Redirect(w, r, "/ui/user", http.StatusFound)
			}
		} else {
			// Not authenticated - redirect to login
			http.Redirect(w, r, "/ui/login", http.StatusFound)
		}
	} else {
		// No auth required - go straight to admin
		http.Redirect(w, r, "/ui/admin", http.StatusFound)
	}
}

// handleLoginPage serves the login page
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check if already authenticated
		if s.isAuthenticated(r) {
			// Already logged in - redirect to appropriate page based on role
			if s.isUserAdmin(r) {
				http.Redirect(w, r, "/ui/admin", http.StatusFound)
			} else {
				http.Redirect(w, r, "/ui/user", http.StatusFound)
			}
			return
		}
		// Serve standalone login page
		s.serveHTMLWithAuth(w, "web/login.html")
	} else {
		// Auth disabled - redirect to admin
		http.Redirect(w, r, "/ui/admin", http.StatusFound)
	}
}

// handleChangePasswordPage serves the change password page
func (s *Server) handleChangePasswordPage(w http.ResponseWriter, r *http.Request) {
	if !s.config.Security.EnableAuth {
		// Auth disabled - redirect to admin
		http.Redirect(w, r, "/ui/admin", http.StatusFound)
		return
	}

	// Check authentication
	if !s.isAuthenticated(r) {
		// Not authenticated - redirect to login
		http.Redirect(w, r, "/ui/login", http.StatusFound)
		return
	}

	// Serve change password page with auth status injected
	s.serveHTMLWithAuth(w, "web/change-password.html")
}

// handleAdminPage serves the admin panel (protected route for admins only)
func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if s.config.Security.EnableAuth {
		// Check authentication
		if !s.isAuthenticated(r) {
			// Not authenticated - redirect to login
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}
		
		// Check if user is admin
		if !s.isUserAdmin(r) {
			// Authenticated but not admin - redirect to user page
			http.Redirect(w, r, "/ui/user", http.StatusFound)
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
			http.Redirect(w, r, "/ui/login", http.StatusFound)
			return
		}
	}
	
	// Serve user page with auth status injected
	s.serveHTMLWithAuth(w, "web/user.html")
}

// isAuthenticated checks if the request has valid authentication
func (s *Server) isAuthenticated(r *http.Request) bool {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	var token string
	
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		// Try cookie
		if cookie, err := r.Cookie("mcp_token"); err == nil {
			token = cookie.Value
		}
	}
	
	if token == "" {
		return false
	}
	
	// Validate token
	_, err := s.db.ValidateToken(token)
	return err == nil
}

// isUserAdmin checks if the authenticated user has admin privileges
func (s *Server) isUserAdmin(r *http.Request) bool {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	var token string
	
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		// Try cookie
		if cookie, err := r.Cookie("mcp_token"); err == nil {
			token = cookie.Value
		}
	}
	
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

func (s *Server) Start() error {
	s.logger.Info().Msg("Starting MCP Gateway Server...")
	
	// Connect to upstream servers at startup
	s.connectToUpstreamServers()
	
	s.logger.Info().Int("upstream_count", len(s.clients)).Msg("MCP Gateway Server started")
	return nil
}