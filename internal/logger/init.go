package logger

import (
	"github.com/nadav-yo/mcp-gateway/pkg/config"
)

// InitializeLoggers initializes all loggers with the provided configuration
func InitializeLoggers(cfg *config.Config) error {
	// Initialize audit logger with rotation config
	if err := InitAuditLogger(&cfg.Logging.Rotation); err != nil {
		Logger.Warn().Err(err).Msg("Failed to initialize audit logger with rotation, using fallback")
	}

	// Set rotation config for server logger
	GetServerLogger().SetRotationConfig(&cfg.Logging.Rotation)

	Logger.Info().Msg("Loggers initialized with rotation configuration")
	return nil
}
