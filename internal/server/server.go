package server

import (
	"context"
	"net/http"
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
	requestLogger := logger.NewRequestLogger()
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
		
		// Gateway-specific endpoints
		mcpRouter.HandleFunc("/gateway/status", s.handleGatewayStatus).Methods("GET")
		mcpRouter.HandleFunc("/gateway/upstream", s.handleUpstreamServers).Methods("GET")
		mcpRouter.HandleFunc("/gateway/stats", s.handleGatewayStats).Methods("GET")
		mcpRouter.HandleFunc("/gateway/refresh", s.handleRefreshConnections).Methods("POST")
		
		// Log endpoints
		mcpRouter.HandleFunc("/api/logs/{filename}", s.handleGenericLog).Methods("GET")
		
		// Register CRUD API routes with auth
		s.upstreamHandler.RegisterRoutes(mcpRouter)
	} else {
		// Unprotected endpoints when auth is disabled
		// SSE endpoint for MCP communication (VS Code uses this)
		r.HandleFunc("/", s.handleSSE).Methods("GET", "POST")
		
		// WebSocket endpoint for MCP communication
		r.HandleFunc("/mcp", s.handleWebSocket)
		
		// HTTP endpoints for MCP over HTTP
		r.HandleFunc("/mcp/http", s.handleHTTP).Methods("POST")
		
		// Gateway-specific endpoints
		r.HandleFunc("/gateway/status", s.handleGatewayStatus).Methods("GET")
		r.HandleFunc("/gateway/upstream", s.handleUpstreamServers).Methods("GET")
		r.HandleFunc("/gateway/stats", s.handleGatewayStats).Methods("GET")
		r.HandleFunc("/gateway/refresh", s.handleRefreshConnections).Methods("POST")
		
		// Log endpoints
		r.HandleFunc("/api/logs/{filename}", s.handleGenericLog).Methods("GET")
		
		// Register CRUD API routes without auth
		s.upstreamHandler.RegisterRoutes(r)
	}

	r.HandleFunc("/admin", s.handleAdminPanel).Methods("GET")
	r.HandleFunc("/health", s.handleHealth).Methods("GET")
	r.HandleFunc("/info", s.handleInfo).Methods("GET")
	// Static file serving for CSS and JS files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/"))))
	
	return r
}

func (s *Server) Start() error {
	s.logger.Info().Msg("Starting MCP Gateway Server...")
	
	// Connect to upstream servers at startup
	s.connectToUpstreamServers()
	
	s.logger.Info().Int("upstream_count", len(s.clients)).Msg("MCP Gateway Server started")
	return nil
}