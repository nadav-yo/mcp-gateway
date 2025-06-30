package local

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

// MCPConfig represents the structure of mcp.json file (similar to VS Code)
type MCPConfig struct {
	Servers          map[string]MCPServerConfig `json:"servers"`
	CurationRegistry *CurationRegistryConfig    `json:"curationRegistry,omitempty"`
}

// CurationRegistryConfig contains curation registry settings
type CurationRegistryConfig struct {
	URL   string `json:"url"`   // Required: URL for curation registry service
	Token string `json:"token"` // Optional: Bearer token for authentication (can be from env)
}

// MCPServerConfig represents a single server configuration in mcp.json
type MCPServerConfig struct {
	Type    string            `json:"type,omitempty"`    // "stdio", "http", "websocket"
	URL     string            `json:"url,omitempty"`     // For http/websocket servers
	Command string            `json:"command,omitempty"` // For stdio servers
	Args    []string          `json:"args,omitempty"`    // Arguments for stdio command
	Headers map[string]string `json:"headers,omitempty"` // HTTP headers
	Timeout string            `json:"timeout,omitempty"` // Connection timeout
	Enabled *bool             `json:"enabled,omitempty"` // Whether server is enabled (defaults to true)
}

// LoadMCPConfig loads and parses the mcp.json file
func LoadMCPConfig(filePath string) (*MCPConfig, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return createDefaultMCPConfig(filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read mcp.json file: %w", err)
	}

	var config MCPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse mcp.json file: %w", err)
	}

	// Load token from environment if not set in config
	if config.CurationRegistry != nil && config.CurationRegistry.Token == "" {
		if envToken := os.Getenv("MCP_CURATION_TOKEN"); envToken != "" {
			config.CurationRegistry.Token = envToken
		}
	}

	return &config, nil
}

// createDefaultMCPConfig creates a default MCP config and writes it to the specified file path
func createDefaultMCPConfig(filePath string) (*MCPConfig, error) {
	// Create default empty config
	defaultConfig := &MCPConfig{
		Servers: make(map[string]MCPServerConfig),
		CurationRegistry: &CurationRegistryConfig{
			URL: "http://localhost:8080", // Default to local gateway
		},
	}

	// Create the directory if it doesn't exist
	if dir := filepath.Dir(filePath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for mcp.json: %w", err)
		}
	}

	// Write default config to file
	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal default config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to create default mcp.json file: %w", err)
	}

	return defaultConfig, nil
}

// Validate validates the MCP configuration
func (mc *MCPConfig) Validate() error {
	// Check required curation registry URL
	if mc.CurationRegistry == nil || mc.CurationRegistry.URL == "" {
		return fmt.Errorf("curationRegistry.url is required and cannot be empty")
	}

	return nil
}

// ToUpstreamServer converts MCPServerConfig to UpstreamServer type
func (msc *MCPServerConfig) ToUpstreamServer(name string) *types.UpstreamServer {
	// Determine server type
	serverType := msc.Type
	if serverType == "" {
		if msc.URL != "" {
			serverType = "http" // Default to HTTP if URL is provided
		} else if msc.Command != "" {
			serverType = "stdio" // Default to STDIO if command is provided
		}
	}

	// Check if enabled (defaults to true)
	enabled := true
	if msc.Enabled != nil {
		enabled = *msc.Enabled
	}

	upstream := &types.UpstreamServer{
		Name:    name,
		Type:    serverType,
		URL:     msc.URL,
		Headers: msc.Headers,
		Timeout: msc.Timeout,
		Enabled: enabled,
	}

	// For STDIO servers, construct command array
	if serverType == "stdio" && msc.Command != "" {
		upstream.Command = append([]string{msc.Command}, msc.Args...)
	}

	return upstream
}

// GetEnabledServers returns a map of enabled upstream servers
func (mc *MCPConfig) GetEnabledServers() map[string]*types.UpstreamServer {
	servers := make(map[string]*types.UpstreamServer)

	for name, serverConfig := range mc.Servers {
		upstream := serverConfig.ToUpstreamServer(name)
		if upstream.Enabled {
			servers[name] = upstream
		}
	}

	return servers
}
