package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nadav-yo/mcp-gateway/internal/logger"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
	"github.com/rs/zerolog"
)

// MCPClient represents a client connection to an upstream MCP server
type MCPClient struct {
	upstream   *types.UpstreamServer
	wsConn     *websocket.Conn
	httpClient *http.Client
	// For stdio connections
	process *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	// Common fields
	mu          sync.RWMutex
	initialized bool
	tools       map[string]*types.Tool
	resources   map[string]*types.Resource
	prompts     map[string]*types.Prompt
	requestID   int64
	ctx         context.Context
	cancel      context.CancelFunc
	logger      zerolog.Logger
	serverID    int64 // Server ID for logging
	// Process synchronization
	processWait sync.Once
	processErr  error
	// Stdio request serialization
	stdioMu sync.Mutex
}

// NewMCPClient creates a new MCP client for the given upstream server
func NewMCPClient(upstream *types.UpstreamServer) *MCPClient {
	return NewMCPClientWithID(upstream, 0)
}

// NewQuietMCPClient creates a new MCP client with disabled logging (for STDIO MCP servers)
func NewQuietMCPClient(upstream *types.UpstreamServer) *MCPClient {
	return NewMCPClientWithID(upstream, -1) // Use -1 to indicate quiet mode
}

// NewMCPClientWithID creates a new MCP client for the given upstream server with a specific server ID
func NewMCPClientWithID(upstream *types.UpstreamServer, serverID int64) *MCPClient {
	ctx, cancel := context.WithCancel(context.Background())

	timeout := 30 * time.Second
	if upstream.Timeout != "" {
		if d, err := time.ParseDuration(upstream.Timeout); err == nil {
			timeout = d
		}
	}

	// Create server-specific logger if serverID is provided
	var clientLogger zerolog.Logger
	if serverID == -1 {
		// Quiet mode for local MCP server - disable all logging to avoid stdout/stderr interference
		clientLogger = zerolog.New(io.Discard).With().Str("upstream", upstream.Name).Logger()
	} else if serverID > 0 {
		if serverLogger, err := logger.GetServerLogger().CreateServerLogger(serverID, upstream.Name); err == nil {
			clientLogger = serverLogger
		} else {
			// Fall back to regular logger if server logger creation fails
			clientLogger = logger.GetLogger("mcp-client").With().Str("upstream", upstream.Name).Logger()
		}
	} else {
		clientLogger = logger.GetLogger("mcp-client").With().Str("upstream", upstream.Name).Logger()
	}

	return &MCPClient{
		upstream: upstream,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		initialized: false,
		tools:       make(map[string]*types.Tool),
		resources:   make(map[string]*types.Resource),
		prompts:     make(map[string]*types.Prompt),
		requestID:   1,
		ctx:         ctx,
		cancel:      cancel,
		logger:      clientLogger,
		serverID:    serverID,
	}
}

// Connect establishes a connection to the upstream MCP server
func (c *MCPClient) Connect() error {
	switch c.upstream.Type {
	case "websocket":
		return c.connectWebSocket()
	case "http":
		return c.connectHTTP()
	case "stdio":
		return c.connectStdio()
	default:
		return fmt.Errorf("unsupported upstream type: %s", c.upstream.Type)
	}
}

// connectWebSocket establishes a WebSocket connection
func (c *MCPClient) connectWebSocket() error {
	headers := http.Header{}

	// Add custom headers from upstream configuration
	for k, v := range c.upstream.Headers {
		headers.Set(k, v)
	}

	// Add authentication headers if configured
	if err := c.addAuthToHeaders(headers); err != nil {
		return fmt.Errorf("failed to add authentication headers: %w", err)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(c.upstream.URL, headers)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.wsConn = conn
	return c.initialize()
}

// connectHTTP tests the HTTP connection
func (c *MCPClient) connectHTTP() error {
	// For HTTP, we just test connectivity by trying to make a request
	return c.initialize()
}

// connectStdio starts the stdio process and connects to it
func (c *MCPClient) connectStdio() error {
	if len(c.upstream.Command) == 0 {
		return fmt.Errorf("no command specified for stdio server")
	}

	c.logger.Info().Strs("command", c.upstream.Command).Msg("Starting stdio process")

	// Create the command
	c.process = exec.CommandContext(c.ctx, c.upstream.Command[0], c.upstream.Command[1:]...)

	// Set up pipes
	stdin, err := c.process.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	c.stdin = stdin

	stdout, err := c.process.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	c.stdout = stdout

	stderr, err := c.process.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	c.stderr = stderr

	// Start the process
	if err := c.process.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	c.logger.Info().Int("pid", c.process.Process.Pid).Msg("Stdio process started")

	// Start monitoring the process
	go c.monitorStdioProcess()

	return c.initialize()
}

// monitorStdioProcess monitors the stdio process and logs stderr
func (c *MCPClient) monitorStdioProcess() {
	// Monitor stderr for logging
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error().Interface("panic", r).Msg("Panic in stderr monitor goroutine")
			}
		}()

		scanner := bufio.NewScanner(c.stderr)
		for scanner.Scan() {
			select {
			case <-c.ctx.Done():
				c.logger.Debug().Msg("Stopping stderr monitoring due to context cancellation")
				return
			default:
				c.logger.Debug().Str("stderr", scanner.Text()).Msg("Process stderr")
			}
		}
		if err := scanner.Err(); err != nil {
			c.logger.Debug().Err(err).Msg("Error reading stderr")
		}
	}()

	// Wait for process to finish
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error().Interface("panic", r).Msg("Panic in process monitor goroutine")
			}
		}()

		// Use sync.Once to ensure Wait() is only called once
		c.processWait.Do(func() {
			c.processErr = c.process.Wait()
		})

		if c.processErr != nil {
			// Only log unexpected exit codes as errors
			// Some processes may exit with status 1 during normal shutdown
			c.logger.Debug().Err(c.processErr).Msg("Stdio process exited with non-zero code")
		} else {
			c.logger.Debug().Msg("Stdio process exited normally")
		}
	}()
}

// initialize performs the MCP initialize handshake
func (c *MCPClient) initialize() error {
	initReq := types.InitializeRequest{
		ProtocolVersion: "2024-11-05",
		Capabilities: types.ClientCapabilities{
			Experimental: make(map[string]interface{}),
		},
		ClientInfo: types.ClientInfo{
			Name:    "mcp-gateway",
			Version: "1.0.0",
		},
	}

	response, err := c.sendRequest("initialize", initReq)
	if err != nil {
		return fmt.Errorf("initialize failed: %w", err)
	}

	if response.Error != nil {
		return fmt.Errorf("initialize error: %s", response.Error.Message)
	}

	c.initialized = true

	// Send the initialized notification to complete the handshake
	// This tells the server that the client has finished processing the initialize response
	if err := c.sendInitializedNotification(); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to send initialized notification")
		// Don't fail, but log the error
	}

	// After initialization, fetch available tools and resources
	c.fetchCapabilities()
	return nil
}

// fetchCapabilities fetches tools, resources, and prompts from the upstream server
func (c *MCPClient) fetchCapabilities() {
	// Fetch tools
	if err := c.fetchTools(); err != nil {
		c.logger.Debug().Err(err).Msg("Failed to fetch tools")
	}

	// Fetch resources
	if err := c.fetchResources(); err != nil {
		c.logger.Debug().Err(err).Msg("Failed to fetch resources")
	}

	// Fetch prompts
	if err := c.fetchPrompts(); err != nil {
		c.logger.Debug().Err(err).Msg("No prompts received from upstream")
	}
}

// fetchTools fetches available tools from the upstream server
func (c *MCPClient) fetchTools() error {
	response, err := c.sendRequest("tools/list", nil)
	if err != nil {
		return err
	}

	if response.Error != nil {
		return fmt.Errorf("tools/list error: %s", response.Error.Message)
	}

	var toolsResp types.ToolListResponse
	// Convert the result to the expected structure
	if resultBytes, err := json.Marshal(response.Result); err == nil {
		if err := json.Unmarshal(resultBytes, &toolsResp); err != nil {
			return fmt.Errorf("failed to parse tools response: %w", err)
		}
	} else {
		return fmt.Errorf("failed to marshal tools response: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, tool := range toolsResp.Tools {
		// Add prefix if configured
		name := tool.Name
		if c.upstream.Prefix != "" {
			name = c.upstream.Prefix + "_" + tool.Name
		}

		toolCopy := tool
		toolCopy.Name = name
		c.tools[name] = &toolCopy
	}

	c.logger.Debug().Int("total_tools", len(c.tools)).Msg("Successfully fetched tools from upstream")
	return nil
}

// fetchResources fetches available resources from the upstream server
func (c *MCPClient) fetchResources() error {
	response, err := c.sendRequest("resources/list", nil)
	if err != nil {
		return err
	}

	if response.Error != nil {
		return fmt.Errorf("resources/list error: %s", response.Error.Message)
	}

	var resourcesResp types.ResourceListResponse
	if resultBytes, err := json.Marshal(response.Result); err == nil {
		if err := json.Unmarshal(resultBytes, &resourcesResp); err != nil {
			return fmt.Errorf("failed to parse resources response: %w", err)
		}
	} else {
		return fmt.Errorf("failed to parse resources response: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, resource := range resourcesResp.Resources {
		// Add prefix if configured
		uri := resource.URI
		if c.upstream.Prefix != "" {
			uri = c.upstream.Prefix + "_" + resource.URI
		}

		resourceCopy := resource
		resourceCopy.URI = uri
		c.resources[uri] = &resourceCopy
	}
	c.logger.Debug().Int("total_resources", len(c.resources)).Msg("Successfully fetched resources from upstream")
	return nil
}

// fetchPrompts fetches available prompts from the upstream server
func (c *MCPClient) fetchPrompts() error {
	response, err := c.sendRequest("prompts/list", map[string]interface{}{})
	if err != nil {
		return err
	}

	if response.Error != nil {
		return fmt.Errorf("prompts/list error: %s", response.Error.Message)
	}

	var promptsResp types.PromptListResponse
	if resultBytes, err := json.Marshal(response.Result); err == nil {
		if err := json.Unmarshal(resultBytes, &promptsResp); err != nil {
			return fmt.Errorf("failed to parse prompts response: %w", err)
		}
	} else {
		return fmt.Errorf("failed to parse prompts response: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, prompt := range promptsResp.Prompts {
		// Add prefix if configured
		name := prompt.Name
		if c.upstream.Prefix != "" {
			name = c.upstream.Prefix + "_" + prompt.Name
		}

		promptCopy := prompt
		promptCopy.Name = name
		c.prompts[name] = &promptCopy
	}
	c.logger.Debug().Int("total_prompts", len(c.prompts)).Msg("Successfully fetched prompts from upstream")
	return nil
}

// sendRequest sends a request to the upstream server
func (c *MCPClient) sendRequest(method string, params interface{}) (*types.MCPResponse, error) {
	if !c.initialized && method != "initialize" {
		return nil, fmt.Errorf("client not initialized")
	}

	c.mu.Lock()
	requestID := c.requestID
	c.requestID++
	c.mu.Unlock()

	var paramsBytes []byte
	var err error
	if params != nil {
		paramsBytes, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal params: %w", err)
		}
	}

	request := &types.MCPRequest{
		JSONRPC: "2.0",
		ID:      requestID,
		Method:  method,
		Params:  paramsBytes,
	}

	var response *types.MCPResponse
	switch c.upstream.Type {
	case "websocket":
		response, err = c.sendWebSocketRequest(request)
	case "http":
		response, err = c.sendHTTPRequest(request)
	case "stdio":
		response, err = c.sendStdioRequest(request)
	default:
		return nil, fmt.Errorf("unsupported upstream type: %s", c.upstream.Type)
	}

	return response, err
}

// sendWebSocketRequest sends a request over WebSocket
func (c *MCPClient) sendWebSocketRequest(request *types.MCPRequest) (*types.MCPResponse, error) {
	if c.wsConn == nil {
		return nil, fmt.Errorf("WebSocket connection not established")
	}

	c.mu.Lock()
	err := c.wsConn.WriteJSON(request)
	c.mu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to send WebSocket request: %w", err)
	}

	// Read response
	var response types.MCPResponse
	c.mu.Lock()
	err = c.wsConn.ReadJSON(&response)
	c.mu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to read WebSocket response: %w", err)
	}

	return &response, nil
}

// sendHTTPRequest sends a request over HTTP
func (c *MCPClient) sendHTTPRequest(request *types.MCPRequest) (*types.MCPResponse, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(c.ctx, "POST", c.upstream.URL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	// Add custom headers from upstream configuration first
	for k, v := range c.upstream.Headers {
		httpReq.Header.Set(k, v)
	}

	// Add authentication headers if configured (this will override any auth headers from custom config)
	if err := c.addAuthHeaders(httpReq); err != nil {
		return nil, fmt.Errorf("failed to add authentication headers: %w", err)
	}

	// Log headers for debugging (excluding sensitive auth info)
	c.logger.Debug().
		Str("url", c.upstream.URL).
		Interface("headers", func() map[string]string {
			headers := make(map[string]string)
			for k, v := range httpReq.Header {
				if k == "Authorization" {
					headers[k] = "[REDACTED]"
				} else {
					headers[k] = strings.Join(v, ", ")
				}
			}
			return headers
		}()).
		Msg("Sending HTTP request")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Check content type to determine how to parse the response
	contentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "text/event-stream") {
		// Handle Server-Sent Events response
		return c.parseSSEResponse(resp.Body)
	} else {
		// Handle regular JSON response
		var response types.MCPResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		return &response, nil
	}
}

// parseSSEResponse parses a Server-Sent Events response and extracts the JSON message
func (c *MCPClient) parseSSEResponse(body io.Reader) (*types.MCPResponse, error) {
	scanner := bufio.NewScanner(body)

	for scanner.Scan() {
		line := scanner.Text()

		// Look for data lines in SSE format
		if strings.HasPrefix(line, "data: ") {
			jsonData := strings.TrimPrefix(line, "data: ")

			// Parse the JSON data
			var response types.MCPResponse
			if err := json.Unmarshal([]byte(jsonData), &response); err != nil {
				return nil, fmt.Errorf("failed to decode SSE JSON: %w", err)
			}

			return &response, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read SSE response: %w", err)
	}

	return nil, fmt.Errorf("no data found in SSE response")
}

// CallTool calls a tool on the upstream server
func (c *MCPClient) CallTool(name string, arguments map[string]interface{}) (*types.CallToolResponse, error) {
	// Remove prefix if present
	originalName := name
	if c.upstream.Prefix != "" && len(name) > len(c.upstream.Prefix)+1 {
		if name[:len(c.upstream.Prefix)+1] == c.upstream.Prefix+"_" {
			originalName = name[len(c.upstream.Prefix)+1:]
		}
	}

	req := types.CallToolRequest{
		Name:      originalName,
		Arguments: arguments,
	}

	response, err := c.sendRequest("tools/call", req)
	if err != nil {
		return nil, err
	}

	if response.Error != nil {
		return nil, fmt.Errorf("tool call error: %s", response.Error.Message)
	}

	var toolResp types.CallToolResponse
	if resultBytes, err := json.Marshal(response.Result); err == nil {
		if err := json.Unmarshal(resultBytes, &toolResp); err != nil {
			return nil, fmt.Errorf("failed to parse tool response: %w", err)
		}
	} else {
		return nil, fmt.Errorf("failed to parse tool response: %w", err)
	}

	// Ensure Content is never nil to prevent "content is not iterable" errors
	if toolResp.Content == nil {
		toolResp.Content = []types.Content{}
	}

	return &toolResp, nil
}

// ReadResource reads a resource from the upstream server
func (c *MCPClient) ReadResource(uri string) (*types.ReadResourceResponse, error) {
	// Remove prefix if present
	originalURI := uri
	if c.upstream.Prefix != "" && len(uri) > len(c.upstream.Prefix)+1 {
		if uri[:len(c.upstream.Prefix)+1] == c.upstream.Prefix+"_" {
			originalURI = uri[len(c.upstream.Prefix)+1:]
		}
	}

	req := types.ReadResourceRequest{
		URI: originalURI,
	}

	response, err := c.sendRequest("resources/read", req)
	if err != nil {
		return nil, err
	}

	if response.Error != nil {
		return nil, fmt.Errorf("resource read error: %s", response.Error.Message)
	}

	var resourceResp types.ReadResourceResponse
	if resultBytes, err := json.Marshal(response.Result); err == nil {
		if err := json.Unmarshal(resultBytes, &resourceResp); err != nil {
			return nil, fmt.Errorf("failed to parse resource response: %w", err)
		}
	} else {
		return nil, fmt.Errorf("failed to parse resource response: %w", err)
	}

	return &resourceResp, nil
}

// GetTools returns the tools available from this upstream server
func (c *MCPClient) GetTools() map[string]*types.Tool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tools := make(map[string]*types.Tool)
	for k, v := range c.tools {
		tools[k] = v
	}
	return tools
}

// GetResources returns the resources available from this upstream server
func (c *MCPClient) GetResources() map[string]*types.Resource {
	c.mu.RLock()
	defer c.mu.RUnlock()

	resources := make(map[string]*types.Resource)
	for k, v := range c.resources {
		resources[k] = v
	}
	return resources
}

// GetPrompts returns the prompts available from this upstream server
func (c *MCPClient) GetPrompts() map[string]*types.Prompt {
	c.mu.RLock()
	defer c.mu.RUnlock()

	prompts := make(map[string]*types.Prompt)
	for k, v := range c.prompts {
		prompts[k] = v
	}
	return prompts
}

// IsConnected returns whether the client is connected and initialized
func (c *MCPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.initialized
}

// Close closes the connection to the upstream server
func (c *MCPClient) Close() error {
	// Cancel the context first to signal all goroutines to stop
	c.cancel()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Mark as not initialized to prevent further operations
	c.initialized = false

	// Close server-specific logger if it exists
	if c.serverID > 0 {
		logger.GetServerLogger().CloseServerLogger(c.serverID)
	}

	if c.wsConn != nil {
		err := c.wsConn.Close()
		c.wsConn = nil
		return err
	}

	// Close stdio process if running
	if c.process != nil {
		// Close stdin to signal the process to exit gracefully
		if c.stdin != nil {
			c.stdin.Close()
			c.stdin = nil
		}

		// Use sync.Once to ensure Wait() is only called once
		// This avoids race condition with monitorStdioProcess goroutine
		done := make(chan error, 1)
		go func() {
			c.processWait.Do(func() {
				c.processErr = c.process.Wait()
			})
			done <- c.processErr
		}()

		var finalErr error

		select {
		case err := <-done:
			if err != nil {
				// Check if this is an expected termination signal
				errMsg := err.Error()
				if errMsg == "signal: killed" || errMsg == "signal: interrupt" || errMsg == "signal: terminated" {
					c.logger.Debug().Err(err).Msg("Stdio process terminated by signal (expected)")
					// Don't return signal terminations as errors since they're expected
					finalErr = nil
				} else {
					c.logger.Debug().Err(err).Msg("Stdio process exited with non-zero code")
					finalErr = err
				}
			} else {
				c.logger.Debug().Msg("Stdio process exited gracefully")
			}
		case <-time.After(3 * time.Second):
			// Process didn't exit gracefully, try termination
			c.logger.Warn().Msg("Stdio process did not exit gracefully, attempting termination")

			if c.process.ProcessState == nil || !c.process.ProcessState.Exited() {
				// Try SIGTERM first, then SIGINT, then force kill
				if err := c.process.Process.Signal(syscall.SIGTERM); err != nil {
					c.logger.Debug().Err(err).Msg("Failed to send SIGTERM, trying SIGINT")
					if err := c.process.Process.Signal(syscall.SIGINT); err != nil {
						c.logger.Debug().Err(err).Msg("Failed to send SIGINT, force killing")
						c.process.Process.Kill()
					}
				}
			} else {
				c.logger.Info().Msg("Stdio process already exited")
			}

			// Wait for termination to complete
			select {
			case err := <-done:
				// Check if this is an expected termination signal
				if err != nil {
					errMsg := err.Error()
					if errMsg == "signal: killed" || errMsg == "signal: interrupt" || errMsg == "signal: terminated" {
						c.logger.Debug().Err(err).Msg("Stdio process terminated by signal (expected)")
						// Don't return signal terminations as errors since they're expected
						finalErr = nil
					} else {
						finalErr = err
					}
				}
			case <-time.After(2 * time.Second):
				c.logger.Warn().Msg("Timeout waiting for stdio process cleanup")
			}
		}

		// Clean up process references
		c.process = nil
		if c.stdout != nil {
			c.stdout.Close()
			c.stdout = nil
		}
		if c.stderr != nil {
			c.stderr.Close()
			c.stderr = nil
		}

		return finalErr
	}

	return nil
}

// addAuthHeaders adds authentication headers to the HTTP request
func (c *MCPClient) addAuthHeaders(req *http.Request) error {
	if c.upstream.Auth == nil {
		c.logger.Debug().Msg("No auth configuration found for upstream")
		return nil
	}

	c.logger.Debug().
		Str("auth_type", c.upstream.Auth.Type).
		Msg("Adding auth headers for upstream")

	switch c.upstream.Auth.Type {
	case "bearer":
		if c.upstream.Auth.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.upstream.Auth.BearerToken)
			c.logger.Debug().Msg("Added Bearer token authorization header")
		} else {
			c.logger.Warn().Msg("Bearer auth configured but no token provided")
		}
	case "basic":
		if c.upstream.Auth.Username != "" && c.upstream.Auth.Password != "" {
			req.SetBasicAuth(c.upstream.Auth.Username, c.upstream.Auth.Password)
			c.logger.Debug().Msg("Added Basic auth authorization header")
		} else {
			c.logger.Warn().Msg("Basic auth configured but username/password missing")
		}
	case "api-key":
		if c.upstream.Auth.APIKey != "" {
			headerName := c.upstream.Auth.HeaderName
			if headerName == "" {
				headerName = "X-API-Key" // Default header name
			}
			req.Header.Set(headerName, c.upstream.Auth.APIKey)
			c.logger.Debug().Str("header_name", headerName).Msg("Added API key header")
		} else {
			c.logger.Warn().Msg("API key auth configured but no API key provided")
		}
	default:
		c.logger.Warn().
			Str("auth_type", c.upstream.Auth.Type).
			Msg("Unknown auth type")
	}

	return nil
}

// addAuthToHeaders adds authentication headers to an http.Header object
func (c *MCPClient) addAuthToHeaders(headers http.Header) error {
	if c.upstream.Auth == nil {
		return nil
	}

	switch c.upstream.Auth.Type {
	case "bearer":
		if c.upstream.Auth.BearerToken != "" {
			headers.Set("Authorization", "Bearer "+c.upstream.Auth.BearerToken)
		}
	case "basic":
		if c.upstream.Auth.Username != "" && c.upstream.Auth.Password != "" {
			// For WebSocket, we need to manually construct the basic auth header
			auth := c.upstream.Auth.Username + ":" + c.upstream.Auth.Password
			encoded := base64.StdEncoding.EncodeToString([]byte(auth))
			headers.Set("Authorization", "Basic "+encoded)
		}
	case "api-key":
		if c.upstream.Auth.APIKey != "" {
			headerName := c.upstream.Auth.HeaderName
			if headerName == "" {
				headerName = "X-API-Key" // Default header name
			}
			headers.Set(headerName, c.upstream.Auth.APIKey)
		}
	}

	return nil
}

// sendStdioRequest sends a request via stdio to the process
func (c *MCPClient) sendStdioRequest(request *types.MCPRequest) (*types.MCPResponse, error) {
	if c.process == nil || c.stdin == nil || c.stdout == nil {
		return nil, fmt.Errorf("stdio process not connected")
	}

	// Serialize all stdio operations to prevent race conditions
	c.stdioMu.Lock()
	defer c.stdioMu.Unlock()

	// Marshal the request to JSON
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send the request followed by a newline
	_, err = c.stdin.Write(append(requestBytes, '\n'))
	if err != nil {
		return nil, fmt.Errorf("failed to write to stdin: %w", err)
	}

	// Read responses until we find the one matching our request ID
	scanner := bufio.NewScanner(c.stdout)

	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("failed to read from stdout: %w", err)
			}
			return nil, fmt.Errorf("no response received from process")
		}

		responseBytes := scanner.Bytes()

		// Parse the response
		var response types.MCPResponse
		if err := json.Unmarshal(responseBytes, &response); err != nil {
			// Log invalid responses but continue reading
			c.logger.Debug().
				Str("raw_response", string(responseBytes)).
				Err(err).
				Msg("Failed to parse response, continuing to read")
			continue
		}

		// Check if this response matches our request ID
		if response.ID == request.ID {
			return &response, nil
		}

		// Log non-matching responses (could be notifications or responses to other requests)
		c.logger.Debug().
			RawJSON("response", responseBytes).
			RawJSON("request", requestBytes).
			Msg("Received unmatched response from stdio process")
	}
}

// GetPrompt calls prompts/get on the upstream server
func (c *MCPClient) GetPrompt(name string, arguments map[string]interface{}) (*types.GetPromptResponse, error) {
	// Remove prefix if present
	originalName := name
	if c.upstream.Prefix != "" && len(name) > len(c.upstream.Prefix)+1 {
		if name[:len(c.upstream.Prefix)+1] == c.upstream.Prefix+"_" {
			originalName = name[len(c.upstream.Prefix)+1:]
		}
	}

	req := types.GetPromptRequest{
		Name:      originalName,
		Arguments: arguments,
	}

	response, err := c.sendRequest("prompts/get", req)
	if err != nil {
		return nil, err
	}

	if response.Error != nil {
		return nil, fmt.Errorf("prompt get error: %s", response.Error.Message)
	}

	var promptResp types.GetPromptResponse
	if resultBytes, err := json.Marshal(response.Result); err == nil {
		if err := json.Unmarshal(resultBytes, &promptResp); err != nil {
			return nil, fmt.Errorf("failed to parse prompt response: %w", err)
		}
	} else {
		return nil, fmt.Errorf("failed to parse prompt response: %w", err)
	}

	return &promptResp, nil
}

// sendInitializedNotification sends the "initialized" notification to complete the MCP handshake
func (c *MCPClient) sendInitializedNotification() error {
	c.logger.Debug().Msg("Sending initialized notification")

	// Create a simple notification structure
	notification := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}

	data, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal initialized notification: %w", err)
	}

	c.logger.Debug().RawJSON("notification", data).Msg("Sending initialized notification data")

	// Send the notification via stdio (no response expected)
	if c.stdin != nil {
		if _, err := c.stdin.Write(data); err != nil {
			return fmt.Errorf("failed to write initialized notification: %w", err)
		}
		if _, err := c.stdin.Write([]byte("\n")); err != nil {
			return fmt.Errorf("failed to write newline after initialized notification: %w", err)
		}
	}

	c.logger.Debug().Msg("Initialized notification sent successfully")
	return nil
}
