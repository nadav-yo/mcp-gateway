package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var Logger zerolog.Logger

func init() {
	// Set up zerolog
	zerolog.TimeFieldFormat = time.RFC3339
	
	// Configure console writer for human-readable output
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "2006-01-02 15:04:05",
	}
	
	Logger = zerolog.New(output).With().Timestamp().Logger()
	
	// Set log level from environment variable, default to INFO
	setLogLevel(os.Getenv("LOG_LEVEL"))
	
	// Set global logger
	log.Logger = Logger
}

// SetLogLevel dynamically sets the log level
func SetLogLevel(level string) {
	setLogLevel(level)
	log.Logger = Logger
}

// setLogLevel is the internal function to set log level
func setLogLevel(level string) {
	logLevel := strings.ToLower(level)
	switch logLevel {
	case "debug":
		Logger = Logger.Level(zerolog.DebugLevel)
	case "info":
		Logger = Logger.Level(zerolog.InfoLevel)
	case "warn", "warning":
		Logger = Logger.Level(zerolog.WarnLevel)
	case "error":
		Logger = Logger.Level(zerolog.ErrorLevel)
	case "fatal":
		Logger = Logger.Level(zerolog.FatalLevel)
	case "panic":
		Logger = Logger.Level(zerolog.PanicLevel)
	default:
		Logger = Logger.Level(zerolog.InfoLevel)
	}
}

// GetLogger returns a logger with additional context
func GetLogger(component string) zerolog.Logger {
	return Logger.With().Str("component", component).Logger()
}

// GetLoggerWithContext returns a logger with multiple context fields
func GetLoggerWithContext(fields map[string]interface{}) zerolog.Logger {
	logContext := Logger.With()
	for key, value := range fields {
		logContext = logContext.Interface(key, value)
	}
	return logContext.Logger()
}
