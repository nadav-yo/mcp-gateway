package logger

import (
	"context"
	"path/filepath"

	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/rs/zerolog"
)

var auditLogger zerolog.Logger
var auditConfig *config.LogRotationConfig

// InitAuditLogger initializes the audit logger with optional rotation configuration
func InitAuditLogger(rotationConfig *config.LogRotationConfig) error {
	auditConfig = rotationConfig
	return initAuditLogger()
}

// initAuditLogger initializes the audit logger with file output
func initAuditLogger() error {
	// Determine the log file path
	auditLogFile := filepath.Join("logs", "audit.log")

	// Get writer with rotation if configured
	writer, err := GetRotatingWriter(auditLogFile, auditConfig)
	if err != nil {
		Logger.Error().Err(err).Msg("Failed to create audit log writer")
		// Fallback to console output
		auditLogger = Logger.With().Str("type", "audit").Logger()
		return err
	}

	// Configure audit logger to write to the rotating writer
	auditLogger = zerolog.New(writer).With().
		Timestamp().
		Str("type", "audit").
		Logger()

	return nil
}

// Audit returns a logger with trace ID from context (if available)
// This is the recommended way to get audit logger with automatic trace correlation
func Audit(ctx context.Context) *zerolog.Logger {
	logger := auditLogger
	if traceID := GetTraceID(ctx); traceID != "" {
		logger = logger.With().Str("trace_id", traceID).Logger()
	}
	return &logger
}

func init() {
	// Initialize with default configuration for backward compatibility
	if err := initAuditLogger(); err != nil {
		// Use console fallback
		auditLogger = Logger.With().Str("type", "audit").Logger()
	}
}
