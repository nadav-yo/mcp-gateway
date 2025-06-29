package local

import (
	"encoding/json"
	"fmt"
	"os"

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
	Type     string            `json:"type,omitempty"`     // "stdio", "http", "websocket"
	URL      string            `json:"url,omitempty"`      // For http/websocket servers
	Command  string            `json:"command,omitempty"`  // For stdio servers
	Args     []string          `json:"args,omitempty"`     // Arguments for stdio command
	Headers  map[string]string `json:"headers,omitempty"`  // HTTP headers
	Timeout  string            `json:"timeout,omitempty"`  // Connection timeout
	Enabled  *bool             `json:"enabled,omitempty"`  // Whether server is enabled (defaults to true)
}

// LoadMCPConfig loads and parses the mcp.json file
func LoadMCPConfig(filePath string) *MCPConfig {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var config MCPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}

	// Load token from environment if not set in config
	if config.CurationRegistry != nil && config.CurationRegistry.Token == "" {
		if envToken := os.Getenv("MCP_CURATION_TOKEN"); envToken != "" {
			config.CurationRegistry.Token = envToken
		}
	}

	return &config
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
