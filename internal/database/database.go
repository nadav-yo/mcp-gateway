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
	// Configure SQLite connection string with optimized settings for concurrency
	connStr := fmt.Sprintf("%s?_busy_timeout=30000&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=2000&_foreign_keys=on&_temp_store=memory&_mmap_size=268435456", dbPath)

	conn, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for better concurrency handling
	conn.SetMaxOpenConns(5)                  // Allow multiple connections for better concurrency
	conn.SetMaxIdleConns(3)                  // Keep some idle connections
	conn.SetConnMaxLifetime(5 * time.Minute) // Rotate connections regularly

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

	// Run database migrations
	if err := db.runMigrations(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
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
		is_admin BOOLEAN DEFAULT false,
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

	CREATE TABLE IF NOT EXISTS curated_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('stdio', 'http', 'ws')),
		url TEXT DEFAULT '',
		command TEXT DEFAULT '[]',
		args TEXT DEFAULT '[]',
		description TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_curated_servers_name ON curated_servers(name);
	CREATE INDEX IF NOT EXISTS idx_curated_servers_type ON curated_servers(type);

	CREATE TABLE IF NOT EXISTS blocked_tools (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_id INTEGER NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('servers', 'curated_servers')),
		tool_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(server_id, type, tool_name)
	);

	CREATE INDEX IF NOT EXISTS idx_blocked_tools_server_id ON blocked_tools(server_id, type);
	CREATE INDEX IF NOT EXISTS idx_blocked_tools_tool_name ON blocked_tools(tool_name);

	CREATE TABLE IF NOT EXISTS blocked_prompts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_id INTEGER NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('servers', 'curated_servers')),
		prompt_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(server_id, type, prompt_name)
	);

	CREATE INDEX IF NOT EXISTS idx_blocked_prompts_server_id ON blocked_prompts(server_id, type);
	CREATE INDEX IF NOT EXISTS idx_blocked_prompts_prompt_name ON blocked_prompts(prompt_name);

	CREATE TABLE IF NOT EXISTS blocked_resources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_id INTEGER NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('servers', 'curated_servers')),
		resource_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(server_id, type, resource_name)
	);

	CREATE INDEX IF NOT EXISTS idx_blocked_resources_server_id ON blocked_resources(server_id, type);
	CREATE INDEX IF NOT EXISTS idx_blocked_resources_resource_name ON blocked_resources(resource_name);
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

// Ping checks if the database connection is healthy
func (db *DB) Ping() error {
	return db.conn.Ping()
}

// HealthCheck performs a comprehensive health check of the database
func (db *DB) HealthCheck() error {
	// Test basic connectivity
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Test a simple query
	var result int
	if err := db.conn.QueryRow("SELECT 1").Scan(&result); err != nil {
		return fmt.Errorf("database query test failed: %w", err)
	}

	return nil
}

// GetDatabaseStats returns SQLite performance statistics
func (db *DB) GetDatabaseStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get connection pool stats
	stats["max_open_connections"] = db.conn.Stats().MaxOpenConnections
	stats["open_connections"] = db.conn.Stats().OpenConnections
	stats["in_use"] = db.conn.Stats().InUse
	stats["idle"] = db.conn.Stats().Idle

	// Get SQLite-specific stats
	var cacheSize, pageSize, pageCount int
	var busyTimeout int

	// Get cache size
	if err := db.conn.QueryRow("PRAGMA cache_size").Scan(&cacheSize); err == nil {
		stats["cache_size"] = cacheSize
	}

	// Get page size
	if err := db.conn.QueryRow("PRAGMA page_size").Scan(&pageSize); err == nil {
		stats["page_size"] = pageSize
	}

	// Get page count
	if err := db.conn.QueryRow("PRAGMA page_count").Scan(&pageCount); err == nil {
		stats["page_count"] = pageCount
		stats["database_size_bytes"] = pageSize * pageCount
	}

	// Get busy timeout
	if err := db.conn.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err == nil {
		stats["busy_timeout_ms"] = busyTimeout
	}

	// Get journal mode
	var journalMode string
	if err := db.conn.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err == nil {
		stats["journal_mode"] = journalMode
	}

	return stats, nil
}

// retryOnBusy executes a database operation with retry logic for SQLITE_BUSY errors
// This should only be used for write operations that might conflict
func (db *DB) retryOnBusy(operation func() error, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := operation()
		if err == nil {
			return nil
		}

		// Check if it's a SQLite busy/locked error
		errStr := err.Error()
		if strings.Contains(errStr, "SQLITE_BUSY") ||
			strings.Contains(errStr, "database is locked") {
			lastErr = err
			// Simple exponential backoff
			backoff := time.Duration(1<<uint(i)) * 10 * time.Millisecond // 10ms, 20ms, 40ms...
			if backoff > 500*time.Millisecond {
				backoff = 500 * time.Millisecond
			}
			time.Sleep(backoff)
			continue
		}

		// Not a busy error, return immediately
		return err
	}
	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, lastErr)
}

// retryOnBusyWithTx executes a database operation within a transaction with retry logic
func (db *DB) retryOnBusyWithTx(operation func(*sql.Tx) error, maxRetries int) error {
	return db.retryOnBusy(func() error {
		tx, err := db.conn.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		defer func() {
			if p := recover(); p != nil {
				tx.Rollback()
				panic(p)
			}
		}()

		if err := operation(tx); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return fmt.Errorf("operation failed: %w, rollback failed: %v", err, rbErr)
			}
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		return nil
	}, maxRetries)
}

// runMigrations handles database schema migrations
func (db *DB) runMigrations() error {
	// Check if is_admin column exists in users table
	rows, err := db.conn.Query("PRAGMA table_info(users)")
	if err != nil {
		return fmt.Errorf("failed to get table info: %w", err)
	}
	defer rows.Close()

	hasIsAdminColumn := false
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue interface{}

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			return fmt.Errorf("failed to scan column info: %w", err)
		}

		if name == "is_admin" {
			hasIsAdminColumn = true
			break
		}
	}

	// Add is_admin column if it doesn't exist
	if !hasIsAdminColumn {
		_, err := db.conn.Exec("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false")
		if err != nil {
			return fmt.Errorf("failed to add is_admin column: %w", err)
		}

		// Make the first user (admin) an admin if exists
		_, err = db.conn.Exec("UPDATE users SET is_admin = true WHERE username = 'admin'")
		if err != nil {
			return fmt.Errorf("failed to update admin user: %w", err)
		}
	}

	// Run curated servers migration
	if err := db.migrateCuratedServers(); err != nil {
		return fmt.Errorf("failed to migrate curated servers: %w", err)
	}

	return nil
}

// migrateCuratedServers populates the curated_servers table with default entries if empty
func (db *DB) migrateCuratedServers() error {
	// Check if curated servers table is empty
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM curated_servers").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check curated servers count: %w", err)
	}

	// If table already has data, skip migration
	if count > 0 {
		return nil
	}

	return nil
}
