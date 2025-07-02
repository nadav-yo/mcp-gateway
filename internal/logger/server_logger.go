package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/rs/zerolog"
)

// ServerLogger manages individual log files for each server
type ServerLogger struct {
	mu             sync.RWMutex
	loggers        map[int64]*serverLoggerEntry
	baseDir        string
	rotationConfig *config.LogRotationConfig
}

// serverLoggerEntry holds both the writer and closer for a server logger
type serverLoggerEntry struct {
	writer io.Writer
	closer io.Closer
}

var serverLogger *ServerLogger
var once sync.Once

// GetServerLogger returns the singleton server logger instance
func GetServerLogger() *ServerLogger {
	once.Do(func() {
		serverLogger = &ServerLogger{
			loggers: make(map[int64]*serverLoggerEntry),
			baseDir: "logs",
		}
	})
	return serverLogger
}

// SetRotationConfig sets the rotation configuration for server logs
func (sl *ServerLogger) SetRotationConfig(config *config.LogRotationConfig) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.rotationConfig = config
}

// CreateServerLogger creates a new log file for a server
func (sl *ServerLogger) CreateServerLogger(serverID int64, serverName string) (zerolog.Logger, error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Close existing logger if it exists
	if existingEntry, exists := sl.loggers[serverID]; exists {
		if existingEntry.closer != nil {
			existingEntry.closer.Close()
		}
		delete(sl.loggers, serverID)
	}

	// Create log file
	logFileName := fmt.Sprintf("server-%d.log", serverID)
	logFilePath := filepath.Join(sl.baseDir, logFileName)

	// Get writer with rotation if configured
	writer, err := GetRotatingWriter(logFilePath, sl.rotationConfig)
	if err != nil {
		return zerolog.Nop(), fmt.Errorf("failed to create log writer for server %d: %w", serverID, err)
	}

	// Store the writer and closer for cleanup
	entry := &serverLoggerEntry{
		writer: writer,
	}
	if closer, ok := writer.(io.Closer); ok {
		entry.closer = closer
	}
	sl.loggers[serverID] = entry

	// Create a JSON logger (similar to request logger)
	logger := zerolog.New(writer).
		With().
		Timestamp().
		Str("component", "mcp-server").
		Int64("server_id", serverID).
		Str("server_name", serverName).
		Logger().
		Level(Logger.GetLevel()) // Use the same level as the global logger

	// Write initial log entry
	logger.Info().Msg("Server logger initialized")

	return logger, nil
}

// CloseServerLogger closes and removes the logger for a server
func (sl *ServerLogger) CloseServerLogger(serverID int64) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if loggerEntry, exists := sl.loggers[serverID]; exists {
		if loggerEntry.closer != nil {
			loggerEntry.closer.Close()
		}
		delete(sl.loggers, serverID)
	}
}

// DeleteServerLog deletes the log file for a server
func (sl *ServerLogger) DeleteServerLog(serverID int64) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Close the logger first if it's open
	if loggerEntry, exists := sl.loggers[serverID]; exists {
		if loggerEntry.closer != nil {
			loggerEntry.closer.Close()
		}
		delete(sl.loggers, serverID)
	}

	// Delete the log file
	logFileName := fmt.Sprintf("server-%d.log", serverID)
	logFilePath := filepath.Join(sl.baseDir, logFileName)

	if _, err := os.Stat(logFilePath); err == nil {
		if err := os.Remove(logFilePath); err != nil {
			return fmt.Errorf("failed to delete log file for server %d: %w", serverID, err)
		}
	}

	return nil
}

// GetServerLogPath returns the path to a server's log file
func (sl *ServerLogger) GetServerLogPath(serverID int64) string {
	logFileName := fmt.Sprintf("server-%d.log", serverID)
	return filepath.Join(sl.baseDir, logFileName)
}

// LogServerEvent logs an event to a specific server's log file
func (sl *ServerLogger) LogServerEvent(serverID int64, level string, message string, fields map[string]interface{}) {
	sl.mu.RLock()
	loggerEntry, exists := sl.loggers[serverID]
	sl.mu.RUnlock()

	if !exists {
		return // Logger not initialized for this server
	}

	// Create a JSON logger for this event (consistent with request logger)
	logger := zerolog.New(loggerEntry.writer).
		With().
		Timestamp().
		Str("component", "mcp-server").
		Int64("server_id", serverID).
		Logger()

	// Add additional fields if provided
	event := logger.Info()
	if level == "error" {
		event = logger.Error()
	} else if level == "warn" {
		event = logger.Warn()
	} else if level == "debug" {
		event = logger.Debug()
	}

	for key, value := range fields {
		event = event.Interface(key, value)
	}

	event.Msg(message)
}

// ListServerLogs returns a list of all server log files
func (sl *ServerLogger) ListServerLogs() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(sl.baseDir, "server-*.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to list server logs: %w", err)
	}

	// Extract just the filenames
	var logFiles []string
	for _, file := range files {
		logFiles = append(logFiles, filepath.Base(file))
	}

	return logFiles, nil
}
