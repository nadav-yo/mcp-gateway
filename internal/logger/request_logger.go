package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/rs/zerolog"
)

// RequestLogger provides request logging middleware
type RequestLogger struct {
	logger zerolog.Logger
}

// NewRequestLogger creates a new request logger that logs to request.log file
func NewRequestLogger() *RequestLogger {
	// Ensure logs directory exists
	logsDir := "logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		// Fallback to console if can't create directory
		return &RequestLogger{
			logger: GetLogger("request"),
		}
	}
	
	// Create or open the request.log file
	logFile := filepath.Join(logsDir, "request.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		// Fallback to console if can't open file
		return &RequestLogger{
			logger: GetLogger("request"),
		}
	}
	
	// Create a file-only logger
	fileLogger := zerolog.New(file).With().
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
		ctx := context.WithValue(r.Context(), "traceID", traceID)
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
		
		// Log the incoming request
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
			Msg("Request received")
		
		// Process the request
		next.ServeHTTP(wrappedWriter, r)
		
		// Log the response
		duration := time.Since(start)
		rl.logger.Info().
			Str("trace_id", traceID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status_code", wrappedWriter.statusCode).
			Dur("duration", duration).
			Int64("user_id", userID).
			Str("username", username).
			Msg("Request completed")
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
	if traceID, ok := ctx.Value("traceID").(string); ok {
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
