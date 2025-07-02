package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"reflect"
	"time"

	"github.com/nadav-yo/mcp-gateway/pkg/config"
	"github.com/rs/zerolog"
)

type contextKey string

const traceIDKey contextKey = "traceID"

// RequestLogger provides request logging middleware
type RequestLogger struct {
	logger zerolog.Logger
}

// NewRequestLogger creates a new request logger that logs to request.log file
func NewRequestLogger() *RequestLogger {
	return NewRequestLoggerWithConfig(nil)
}

// NewRequestLoggerWithConfig creates a new request logger with rotation configuration
func NewRequestLoggerWithConfig(rotationConfig *config.LogRotationConfig) *RequestLogger {
	// Create the log file path
	logFile := filepath.Join("logs", "request.log")

	// Get writer with rotation if configured
	writer, err := GetRotatingWriter(logFile, rotationConfig)
	if err != nil {
		// Fallback to console if can't create rotating writer
		return &RequestLogger{
			logger: GetLogger("request"),
		}
	}

	// Create a file-only logger
	fileLogger := zerolog.New(writer).With().
		Timestamp().
		Str("component", "request").
		Logger()

	return &RequestLogger{
		logger: fileLogger,
	}
}

// generateTraceID generates a unique trace ID for each request
func generateTraceID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// getUserFromContext extracts user information from the request context
func getUserFromContext(ctx context.Context) (userID int64, username string) {
	if user := ctx.Value("user"); user != nil {
		// Use reflection to extract UserID and Username without importing database package
		userVal := reflect.ValueOf(user)
		if userVal.Kind() == reflect.Ptr {
			userVal = userVal.Elem()
		}

		if userVal.Kind() == reflect.Struct {
			userIDField := userVal.FieldByName("UserID")
			usernameField := userVal.FieldByName("Username")

			if userIDField.IsValid() && userIDField.CanInterface() {
				if id, ok := userIDField.Interface().(int64); ok {
					userID = id
				}
			}

			if usernameField.IsValid() && usernameField.CanInterface() {
				if name, ok := usernameField.Interface().(string); ok {
					username = name
				}
			}

			if userID != 0 && username != "" {
				return userID, username
			}
		}

		return 0, "authenticated_user"
	}
	return 0, "anonymous"
}

// Middleware logs all incoming requests with trace IDs and user information
func (rl *RequestLogger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		traceID := generateTraceID()

		// Add trace ID to request context
		ctx := context.WithValue(r.Context(), traceIDKey, traceID)
		r = r.WithContext(ctx)

		// Add trace ID to response headers for debugging
		w.Header().Set("X-Trace-ID", traceID)

		// Extract user information (will be available after auth middleware)
		userID, username := getUserFromContext(r.Context())

		// Create a response writer wrapper to capture status code
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     200, // default status code
		}

		// Process the request
		next.ServeHTTP(wrappedWriter, r)

		// Log the complete request with all information
		duration := time.Since(start)
		rl.logger.Info().
			Str("trace_id", traceID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("query", r.URL.RawQuery).
			Str("remote_addr", r.RemoteAddr).
			Str("user_agent", r.Header.Get("User-Agent")).
			Int64("user_id", userID).
			Str("username", username).
			Str("content_type", r.Header.Get("Content-Type")).
			Int64("content_length", r.ContentLength).
			Int("status_code", wrappedWriter.statusCode).
			Dur("duration", duration).
			Msg("Request processed")
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

// GetTraceID extracts the trace ID from the request context
func GetTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value(traceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// LogWithTrace returns a logger with trace ID context
func LogWithTrace(ctx context.Context, component string) zerolog.Logger {
	logger := GetLogger(component)
	if traceID := GetTraceID(ctx); traceID != "" {
		logger = logger.With().Str("trace_id", traceID).Logger()
	}
	return logger
}
