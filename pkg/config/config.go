package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	MCP      MCPConfig      `yaml:"mcp"`
	Gateway  GatewayConfig  `yaml:"gateway"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	Port            int    `yaml:"port"`
	Host            string `yaml:"host"`
	ReadTimeout     string `yaml:"read_timeout"`
	WriteTimeout    string `yaml:"write_timeout"`
	ShutdownTimeout string `yaml:"shutdown_timeout"`
}

// MCPConfig contains MCP-specific settings
type MCPConfig struct {
	Version     string              `yaml:"version"`
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Tools       []ToolConfig        `yaml:"tools"`
	Resources   []ResourceConfig    `yaml:"resources"`
	Capabilities MCPCapabilities    `yaml:"capabilities"`
}

// GatewayConfig contains gateway-specific settings
type GatewayConfig struct {
	ConnectionTimeout   string `yaml:"connection_timeout"`
	RequestTimeout      string `yaml:"request_timeout"`
	RetryAttempts       int    `yaml:"retry_attempts"`
	RetryDelay          string `yaml:"retry_delay"`
	EnableHealthCheck   bool   `yaml:"enable_health_check"`
	HealthCheckInterval string `yaml:"health_check_interval"`
}

// ToolConfig defines available tools
type ToolConfig struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	InputSchema map[string]interface{} `yaml:"input_schema"`
}

// ResourceConfig defines available resources
type ResourceConfig struct {
	URI         string `yaml:"uri"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	MimeType    string `yaml:"mime_type"`
}

// MCPCapabilities defines server capabilities
type MCPCapabilities struct {
	Tools     ToolCapabilities     `yaml:"tools"`
	Resources ResourceCapabilities `yaml:"resources"`
	Logging   LoggingCapabilities  `yaml:"logging"`
}

type ToolCapabilities struct {
	ListChanged bool `yaml:"list_changed"`
}

type ResourceCapabilities struct {
	Subscribe   bool `yaml:"subscribe"`
	ListChanged bool `yaml:"list_changed"`
}

type LoggingCapabilities struct {
	Level string `yaml:"level"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	EnableAuth bool     `yaml:"enable_auth"`
	APIKeys    []string `yaml:"api_keys"`
	AllowedIPs []string `yaml:"allowed_ips"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// Load loads configuration from file
func Load(configPath string) (*Config, error) {
	// Set default configuration
	config := &Config{
		Server: ServerConfig{
			Port:            8080,
			Host:            "0.0.0.0",
			ReadTimeout:     "30s",
			WriteTimeout:    "30s",
			ShutdownTimeout: "30s",
		},
		MCP: MCPConfig{
			Version:     "2024-11-05",
			Name:        "mcp-gateway",
			Description: "MCP Remote Server Gateway",
			Capabilities: MCPCapabilities{
				Tools:     ToolCapabilities{ListChanged: false},
				Resources: ResourceCapabilities{Subscribe: false, ListChanged: false},
				Logging:   LoggingCapabilities{Level: "info"},
			},
		},
		Gateway: GatewayConfig{
			ConnectionTimeout:   "30s",
			RequestTimeout:      "30s",
			RetryAttempts:       3,
			RetryDelay:          "1s",
			EnableHealthCheck:   true,
			HealthCheckInterval: "60s",
		},
		Security: SecurityConfig{
			EnableAuth: true,
			APIKeys:    []string{},
			AllowedIPs: []string{},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil // Return default config if file doesn't exist
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// Save saves configuration to file
func (c *Config) Save(configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
