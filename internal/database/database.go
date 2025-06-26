package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nadav-yo/mcp-gateway/internal/secrets"
)

// DB represents the database connection and operations
type DB struct {
	conn          *sql.DB
	secretManager *secrets.SecretManager
}

// New creates a new database connection and initializes tables
func New(dbPath string) (*DB, error) {
	// Configure SQLite connection string with proper settings for concurrency
	connStr := fmt.Sprintf("%s?_busy_timeout=10000&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=1000&_foreign_keys=on", dbPath)
	
	conn, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for better concurrency handling
	conn.SetMaxOpenConns(25)   // Limit concurrent connections
	conn.SetMaxIdleConns(5)    // Keep some idle connections
	conn.SetConnMaxLifetime(0) // No connection lifetime limit for SQLite

	// Test the connection
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	secretManager, err := secrets.NewSecretManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	db := &DB{
		conn:          conn,
		secretManager: secretManager,
	}

	if err := db.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

// createTables creates the necessary database tables
func (db *DB) createTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS upstream_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		url TEXT DEFAULT '',
		command TEXT DEFAULT '[]',
		type TEXT NOT NULL CHECK(type IN ('websocket', 'http', 'stdio')),
		headers TEXT DEFAULT '{}',
		timeout TEXT DEFAULT '30s',
		enabled BOOLEAN DEFAULT true,
		prefix TEXT DEFAULT '',
		description TEXT DEFAULT '',
		auth_type TEXT DEFAULT '' CHECK(auth_type IN ('', 'bearer', 'basic', 'api-key')),
		auth_token TEXT DEFAULT '',
		auth_username TEXT DEFAULT '',
		auth_password TEXT DEFAULT '',
		auth_api_key TEXT DEFAULT '',
		auth_header_name TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME,
		status TEXT DEFAULT 'disconnected' CHECK(status IN ('connected', 'disconnected', 'error', 'starting'))
	);

	CREATE INDEX IF NOT EXISTS idx_upstream_servers_name ON upstream_servers(name);
	CREATE INDEX IF NOT EXISTS idx_upstream_servers_enabled ON upstream_servers(enabled);
	CREATE INDEX IF NOT EXISTS idx_upstream_servers_status ON upstream_servers(status);

	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_active BOOLEAN DEFAULT true,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token TEXT UNIQUE NOT NULL,
		user_id INTEGER NOT NULL,
		username TEXT NOT NULL,
		description TEXT DEFAULT '',
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME,
		is_active BOOLEAN DEFAULT true,
		is_internal BOOLEAN DEFAULT false,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_tokens_username ON tokens(username);
	`

	_, err := db.conn.Exec(query)
	if err != nil {
		return err
	}

	// Initialize default admin user if it doesn't exist
	return db.initializeDefaultUser()
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// retryOnBusy executes a database operation with retry logic for SQLITE_BUSY errors
func (db *DB) retryOnBusy(operation func() error, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := operation()
		if err == nil {
			return nil
		}
		
		// Check if it's a SQLITE_BUSY error
		if strings.Contains(err.Error(), "SQLITE_BUSY") || strings.Contains(err.Error(), "database is locked") {
			lastErr = err
			// Exponential backoff with jitter
			backoff := time.Duration(i+1) * 50 * time.Millisecond
			if i > 2 {
				backoff = time.Duration(i-2) * 100 * time.Millisecond
			}
			time.Sleep(backoff)
			continue
		}
		
		// Not a busy error, return immediately
		return err
	}
	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, lastErr)
}
