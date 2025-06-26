package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nadav-yo/mcp-gateway/internal/database"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/internal/server"
	"github.com/nadav-yo/mcp-gateway/pkg/config"
)

func main() {
	var configPath string
	var dbPath string
	flag.StringVar(&configPath, "config", "config.yaml", "Path to configuration file")
	flag.StringVar(&dbPath, "db", "mcp-gateway.db", "Path to SQLite database file")
	flag.Parse()

	// Initialize logger
	log := logger.GetLogger("main")

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer db.Close()

	// Create MCP gateway server
	mcpServer := server.New(cfg, db)
	
	// Initialize gateway connections
	if err := mcpServer.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start MCP gateway")
	}

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: mcpServer.Router(),
	}

	// Start server in a goroutine
	go func() {
		log.Info().Int("port", cfg.Server.Port).Msg("Starting MCP Gateway Server")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down MCP Gateway Server...")

	// Shutdown gateway connections
	if err := mcpServer.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down gateway")
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("MCP Gateway Server exited")
}
