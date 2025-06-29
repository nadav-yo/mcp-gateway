package local

import (
	"encoding/json"
	"fmt"

	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

// MCPLogger handles MCP-compliant logging via JSON-RPC notifications
type MCPLogger struct {
	enabled bool
	level   string
}

// NewMCPLogger creates a new MCP-compliant logger
func NewMCPLogger() *MCPLogger {
	return &MCPLogger{
		enabled: true,
		level:   "info",
	}
}

// SetLevel sets the logging level
func (l *MCPLogger) SetLevel(level string) {
	l.level = level
}

// sendLogNotification sends a log notification via JSON-RPC
func (l *MCPLogger) sendLogNotification(level, logger, message string) {
	if !l.enabled || !l.shouldLog(level) {
		return
	}

	notification := types.MCPNotification{
		JSONRPC: "2.0",
		Method:  "notifications/message",
		Params: map[string]interface{}{
			"level":  level,
			"logger": logger,
			"data":   message,
		},
	}

	// Send to stdout as JSON-RPC notification
	if jsonBytes, err := json.Marshal(notification); err == nil {
		fmt.Println(string(jsonBytes))
	}
}

// shouldLog determines if a message should be logged based on current level
func (l *MCPLogger) shouldLog(messageLevel string) bool {
	levels := map[string]int{
		"debug":     0,
		"info":      1,
		"notice":    2,
		"warning":   3,
		"error":     4,
		"critical":  5,
		"alert":     6,
		"emergency": 7,
	}

	currentLevel, exists := levels[l.level]
	if !exists {
		currentLevel = 1 // default to info
	}

	msgLevel, exists := levels[messageLevel]
	if !exists {
		msgLevel = 1 // default to info
	}

	return msgLevel >= currentLevel
}

// Log methods
func (l *MCPLogger) Debug(logger, message string) {
	l.sendLogNotification("debug", logger, message)
}

func (l *MCPLogger) Info(logger, message string) {
	l.sendLogNotification("info", logger, message)
}

func (l *MCPLogger) Warning(logger, message string) {
	l.sendLogNotification("warning", logger, message)
}

func (l *MCPLogger) Error(logger, message string) {
	l.sendLogNotification("error", logger, message)
}

func (l *MCPLogger) Critical(logger, message string) {
	l.sendLogNotification("critical", logger, message)
}

// Global MCP logger instance
var mcpLogger *MCPLogger

// InitMCPLogger initializes the global MCP logger
func InitMCPLogger() {
	mcpLogger = NewMCPLogger()
}

// GetMCPLogger returns the global MCP logger
func GetMCPLogger() *MCPLogger {
	if mcpLogger == nil {
		InitMCPLogger()
	}
	return mcpLogger
}
