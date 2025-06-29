package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nadav-yo/mcp-gateway/internal/local"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

func main() {
	var gatewayURL string
	var mcpConfigPath string
	var debug bool

	flag.StringVar(&gatewayURL, "gateway", "", "URL of the MCP gateway to connect to for approved server list")
	flag.StringVar(&mcpConfigPath, "mcp-config", "mcp.json", "Path to mcp.json file with upstream servers")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// Initialize MCP-compliant logger for STDIO mode
	local.InitMCPLogger()
	mcpLog := local.GetMCPLogger()
	if debug {
		mcpLog.SetLevel("debug")
	}

	// Also keep the regular logger for startup/shutdown messages that go to stderr
	log := logger.GetLogger("mcp-local")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info().Msg("Shutdown signal received")
		cancel()
	}()

	// Use default configuration for local MCP server
	cfg := getDefaultLocalConfig()

	// Create local MCP server
	server, err := local.NewMCPServerWithConfig(cfg, gatewayURL, mcpConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create MCP server")
	}

	// Set the MCP logger for the server
	server.SetMCPLogger(mcpLog)

	// Start the server with stdio transport
	if err := server.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start MCP server")
	}

	// STDIO communication loop
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		var request types.MCPRequest
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			log.Error().Err(err).Str("input", line).Msg("Failed to parse JSON request")
			writeErrorResponse(nil, -32700, "Parse error", err.Error())
			continue
		}

		response := server.HandleRequest(&request)
		if response != nil {
			responseBytes, err := json.Marshal(response)
			if err != nil {
				log.Error().Err(err).Msg("Failed to marshal response")
				writeErrorResponse(request.ID, -32603, "Internal error", "Failed to marshal response")
				continue
			}

			fmt.Println(string(responseBytes))
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error().Err(err).Msg("Error reading from stdin")
	}

	log.Info().Msg("Local MCP Server stopped")
}

// writeErrorResponse writes an error response to stdout
func writeErrorResponse(id interface{}, code int, message, data string) {
	response := &types.MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &types.MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	responseBytes, _ := json.Marshal(response)
	fmt.Println(string(responseBytes))
}

// getDefaultLocalConfig returns a default configuration for the local MCP server
func getDefaultLocalConfig() *config.Config {
	return &config.Config{
		MCP: config.MCPConfig{
			Version:     "2024-11-05",
			Name:        "mcp-local",
			Description: "Local MCP Server with Gateway Integration",
			Capabilities: config.MCPCapabilities{
				Tools: config.ToolCapabilities{
					ListChanged: false,
				},
				Resources: config.ResourceCapabilities{
					Subscribe:   false,
					ListChanged: false,
				},
				Logging: config.LoggingCapabilities{
					Level: "info",
				},
			},
			Tools:     []config.ToolConfig{},
			Resources: []config.ResourceConfig{},
		},
		Security: config.SecurityConfig{
			EnableAuth: false, // Local server doesn't need auth by default
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stderr", // Use stderr for logs so stdout is only for MCP communication
		},
	}
}
