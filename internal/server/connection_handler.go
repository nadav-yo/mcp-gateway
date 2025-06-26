package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

// handleWebSocket handles WebSocket connections for MCP protocol
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	defer conn.Close()

	s.logger.Info().Msg("New WebSocket connection established")

	// Set up a channel to handle graceful shutdown
	done := make(chan struct{})
	defer close(done)

	// Goroutine to handle reading messages
	go func() {
		defer func() {
			select {
			case done <- struct{}{}:
			default:
			}
		}()
		
		for {
			var req types.MCPRequest
			if err := conn.ReadJSON(&req); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					s.logger.Error().Err(err).Msg("WebSocket error")
				}
				return
			}

			response := s.handleMCPRequest(&req)
			
			if err := conn.WriteJSON(response); err != nil {
				s.logger.Error().Err(err).Msg("WebSocket write error")
				return
			}
		}
	}()

	// Wait for either connection to close or server to shutdown
	select {
	case <-done:
		// Connection closed normally
	case <-s.ctx.Done():
		// Server shutting down
		s.logger.Info().Msg("WebSocket connection closing due to server shutdown")
	}
}

// handleHTTP handles HTTP requests for MCP protocol
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var req types.MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	response := s.handleMCPRequest(&req)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error().Err(err).Msg("Failed to encode response")
	}
}

// handleSSE handles Server-Sent Events for MCP protocol (used by VS Code)
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Handle SSE connection setup for VS Code
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")
		
		// For VS Code MCP, we need to handle the connection differently
		// VS Code expects to be able to send messages via POST and receive responses
		// The GET request is just to establish the SSE connection
		
		// Create a channel to keep the connection alive
		done := make(chan bool)
		
		// Set up a goroutine to keep connection alive
		go func() {
			defer close(done)
			// Send periodic keep-alive messages
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					// Send keep-alive
					fmt.Fprint(w, ": keep-alive\n\n")
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
				case <-r.Context().Done():
					// Context cancelled, stop immediately
					return
				case <-done:
					// Connection closed, stop immediately
					return
				case <-s.ctx.Done():
					// Server shutting down, stop immediately
					return
				}
			}
		}()
		
		// Wait for connection to close or server shutdown
		select {
		case <-r.Context().Done():
		case <-s.ctx.Done():
		}
		return
	}
	
	if r.Method == "POST" {
		// Handle MCP messages sent via POST to SSE endpoint
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		var req types.MCPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		response := s.handleMCPRequest(&req)
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			s.logger.Error().Err(err).Msg("Failed to encode response")
		}
		return
	}
	
	// Handle other methods
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
