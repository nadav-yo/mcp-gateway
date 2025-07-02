package types

import "encoding/json"

// MCPRequest represents a generic MCP request
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse represents a generic MCP response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPNotification represents a generic MCP notification (no ID)
type MCPNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// InitializeRequest represents the initialize request
type InitializeRequest struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

// InitializeResponse represents the initialize response
type InitializeResponse struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// ClientCapabilities represents client capabilities
type ClientCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Sampling     *SamplingCapability    `json:"sampling,omitempty"`
}

// SamplingCapability represents sampling capability
type SamplingCapability struct{}

// ServerCapabilities represents server capabilities
type ServerCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Logging      *LoggingCapability     `json:"logging,omitempty"`
	Prompts      *PromptCapability      `json:"prompts,omitempty"`
	Resources    *ResourceCapability    `json:"resources,omitempty"`
	Tools        *ToolCapability        `json:"tools,omitempty"`
}

// LoggingCapability represents logging capability
type LoggingCapability struct{}

// ResourceCapability represents resource capability
type ResourceCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// ToolCapability represents tool capability
type ToolCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptCapability represents prompt capability
type PromptCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ClientInfo represents client information
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerInfo represents server information
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool represents an MCP tool
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolListResponse represents the response to tools/list
type ToolListResponse struct {
	Tools []Tool `json:"tools"`
}

// CallToolRequest represents a tool call request
type CallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// CallToolResponse represents a tool call response
type CallToolResponse struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content represents content in responses
type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Resource represents an MCP resource
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceListResponse represents the response to resources/list
type ResourceListResponse struct {
	Resources []Resource `json:"resources"`
}

// ReadResourceRequest represents a resource read request
type ReadResourceRequest struct {
	URI string `json:"uri"`
}

// ReadResourceResponse represents a resource read response
type ReadResourceResponse struct {
	Contents []ResourceContent `json:"contents"`
}

// ResourceContent represents resource content
type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// Prompt represents an MCP prompt
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptArgument represents a prompt argument
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptListResponse represents the response to prompts/list
type PromptListResponse struct {
	Prompts []Prompt `json:"prompts"`
}

// GetPromptRequest represents a prompt get request
type GetPromptRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// GetPromptResponse represents a prompt get response
type GetPromptResponse struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptMessage represents a prompt message
type PromptMessage struct {
	Role    string    `json:"role"`
	Content []Content `json:"content"`
}

// LoggingSetLevelRequest represents a logging level set request
type LoggingSetLevelRequest struct {
	Level string `json:"level"`
}

// Notification represents an MCP notification
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// UpstreamServer represents configuration for an upstream MCP server
type UpstreamServer struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`               // For websocket/http servers
	Command []string          `json:"command,omitempty"` // For stdio servers (e.g., ["npx", "name", "--variables"])
	Type    string            `json:"type"`              // "websocket", "http", "stdio"
	Headers map[string]string `json:"headers,omitempty"`
	Timeout string            `json:"timeout,omitempty"`
	Enabled bool              `json:"enabled"`
	Prefix  string            `json:"prefix,omitempty"` // Prefix for tools/resources from this server
	Auth    *AuthConfig       `json:"auth,omitempty"`   // Authentication configuration
}

// AuthConfig represents authentication configuration for upstream servers
type AuthConfig struct {
	Type        string `json:"type"`                   // "bearer", "basic", "api-key"
	BearerToken string `json:"bearer_token,omitempty"` // Bearer token (will be encrypted in storage)
	Username    string `json:"username,omitempty"`     // For basic auth
	Password    string `json:"password,omitempty"`     // For basic auth (will be encrypted in storage)
	APIKey      string `json:"api_key,omitempty"`      // API key (will be encrypted in storage)
	HeaderName  string `json:"header_name,omitempty"`  // Custom header name for API key
}

// ClientConnection represents a connection to an upstream MCP server
type ClientConnection struct {
	Server      *UpstreamServer
	Connected   bool
	LastError   error
	Tools       map[string]*Tool
	Resources   map[string]*Resource
	Prompts     map[string]*Prompt
	Initialized bool
}

// GatewayStats represents gateway statistics
type GatewayStats struct {
	UpstreamServers   int `json:"upstream_servers"`
	ConnectedServers  int `json:"connected_servers"`
	TotalTools        int `json:"total_tools"`
	TotalResources    int `json:"total_resources"`
	TotalPrompts      int `json:"total_prompts"`
	RequestsProcessed int `json:"requests_processed"`

	// Additional statistics
	ActiveTokens          int            `json:"active_tokens"`
	TotalUsers            int            `json:"total_users"`
	TotalBlockedTools     int            `json:"total_blocked_tools"`
	TotalBlockedPrompts   int            `json:"total_blocked_prompts"`
	TotalBlockedResources int            `json:"total_blocked_resources"`
	ServersByStatus       map[string]int `json:"servers_by_status"`
	ServersByType         map[string]int `json:"servers_by_type"`
	AuthMethodsCount      map[string]int `json:"auth_methods_count"`
	SystemUptime          string         `json:"system_uptime"`
	LastDatabaseUpdate    string         `json:"last_database_update"`
}
