package logger

import (
	"io"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
	"github.com/nadav-yo/mcp-gateway/pkg/config"
)

// GetRotatingWriter returns an io.Writer with log rotation capabilities
// If rotation is disabled, it returns a standard file writer
func GetRotatingWriter(logFilePath string, config *config.LogRotationConfig) (io.Writer, error) {
	// Create logs directory if it doesn't exist
	logsDir := filepath.Dir(logFilePath)
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return nil, err
	}

	// If rotation is disabled, use standard file writer
	if config == nil || !config.Enabled {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		return file, nil
	}

	// Use lumberjack for rotating logs
	rotatingWriter := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    config.MaxSizeMB,    // megabytes
		MaxBackups: config.MaxBackups,   // number of backups
		MaxAge:     config.MaxAgeDays,   // days
		Compress:   config.Compress,     // compress with gzip
	}

	return rotatingWriter, nil
}

// GetRotatingWriterWithDefaults returns a rotating writer with default settings
func GetRotatingWriterWithDefaults(logFilePath string) (io.Writer, error) {
	defaultConfig := &config.LogRotationConfig{
		Enabled:    true,
		MaxSizeMB:  100,
		MaxBackups: 5,
		MaxAgeDays: 30,
		Compress:   true,
	}
	return GetRotatingWriter(logFilePath, defaultConfig)
}
