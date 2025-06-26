package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"github.com/nadav-yo/mcp-gateway/internal/secrets"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

// DB represents the database connection and operations
type DB struct {
	conn          *sql.DB
	secretManager *secrets.SecretManager
}

// UpstreamServerRecord represents an upstream server record in the database
type UpstreamServerRecord struct {
	ID              int64                 `json:"id" db:"id"`
	Name            string                `json:"name" db:"name"`
	URL             string                `json:"url" db:"url"`
	Command         []string              `json:"command" db:"command"`         // Will be JSON marshaled for stdio servers
	Type            string                `json:"type" db:"type"`
	Headers         map[string]string     `json:"headers" db:"headers"` // Will be JSON marshaled
	Timeout         string                `json:"timeout" db:"timeout"`
	Enabled         bool                  `json:"enabled" db:"enabled"`
	Prefix          string                `json:"prefix" db:"prefix"`
	Description     string                `json:"description" db:"description"`
	AuthType        string                `json:"auth_type" db:"auth_type"`           // bearer, basic, api-key
	AuthToken       string                `json:"auth_token" db:"auth_token"`         // Encrypted bearer token
	AuthUsername    string                `json:"auth_username" db:"auth_username"`   // Username for basic auth
	AuthPassword    string                `json:"auth_password" db:"auth_password"`   // Encrypted password for basic auth
	AuthAPIKey      string                `json:"auth_api_key" db:"auth_api_key"`     // Encrypted API key
	AuthHeaderName  string                `json:"auth_header_name" db:"auth_header_name"` // Custom header name for API key
	CreatedAt       time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at" db:"updated_at"`
	LastSeen        *time.Time            `json:"last_seen" db:"last_seen"`
	Status          string                `json:"status" db:"status"` // connected, disconnected, error
}

// UserRecord represents a user record in the database
type UserRecord struct {
	ID        int64     `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Password  string    `json:"-" db:"password_hash"` // Hashed password, not returned in JSON
	IsActive  bool      `json:"is_active" db:"is_active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TokenRecord represents an access token record in the database
type TokenRecord struct {
	ID          int64      `json:"id" db:"id"`
	Token       string     `json:"token" db:"token"`
	UserID      int64      `json:"user_id" db:"user_id"`
	Username    string     `json:"username" db:"username"`
	Description string     `json:"description" db:"description"`
	ExpiresAt   *time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	LastUsed    *time.Time `json:"last_used" db:"last_used"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	IsInternal  bool       `json:"is_internal" db:"is_internal"`
}

// New creates a new database connection and initializes tables
func New(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
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

// CreateUpstreamServer creates a new upstream server
func (db *DB) CreateUpstreamServer(server *UpstreamServerRecord) (*UpstreamServerRecord, error) {
	headersJSON, err := json.Marshal(server.Headers)
	if err != nil {
		headersJSON = []byte("{}")
	}

	commandJSON, err := json.Marshal(server.Command)
	if err != nil {
		commandJSON = []byte("[]")
	}

	// Encrypt sensitive authentication data
	encryptedToken, err := db.secretManager.Encrypt(server.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth token: %w", err)
	}

	encryptedPassword, err := db.secretManager.Encrypt(server.AuthPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth password: %w", err)
	}

	encryptedAPIKey, err := db.secretManager.Encrypt(server.AuthAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth API key: %w", err)
	}

	query := `
	INSERT INTO upstream_servers (name, url, command, type, headers, timeout, enabled, prefix, description,
								  auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query,
		server.Name, server.URL, string(commandJSON), server.Type, string(headersJSON),
		server.Timeout, server.Enabled, server.Prefix, server.Description,
		server.AuthType, encryptedToken, server.AuthUsername, encryptedPassword, encryptedAPIKey, server.AuthHeaderName)
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream server: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetUpstreamServer(id)
}

// GetUpstreamServer retrieves an upstream server by ID
func (db *DB) GetUpstreamServer(id int64) (*UpstreamServerRecord, error) {
	query := `
	SELECT id, name, url, command, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers WHERE id = ?
	`

	row := db.conn.QueryRow(query, id)

	var server UpstreamServerRecord
	var headersJSON, commandJSON string
	var encryptedToken, encryptedPassword, encryptedAPIKey string

	err := row.Scan(
		&server.ID, &server.Name, &server.URL, &commandJSON, &server.Type, &headersJSON,
		&server.Timeout, &server.Enabled, &server.Prefix, &server.Description,
		&server.AuthType, &encryptedToken, &server.AuthUsername, &encryptedPassword, &encryptedAPIKey, &server.AuthHeaderName,
		&server.CreatedAt, &server.UpdatedAt, &server.LastSeen, &server.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream server: %w", err)
	}

	// Unmarshal headers
	if err := json.Unmarshal([]byte(headersJSON), &server.Headers); err != nil {
		server.Headers = make(map[string]string)
	}

	// Unmarshal command
	if err := json.Unmarshal([]byte(commandJSON), &server.Command); err != nil {
		server.Command = []string{}
	}

	// Decrypt sensitive authentication data
	server.AuthToken, err = db.secretManager.Decrypt(encryptedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth token: %w", err)
	}

	server.AuthPassword, err = db.secretManager.Decrypt(encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth password: %w", err)
	}

	server.AuthAPIKey, err = db.secretManager.Decrypt(encryptedAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth API key: %w", err)
	}

	return &server, nil
}

// GetUpstreamServerByName retrieves an upstream server by name
func (db *DB) GetUpstreamServerByName(name string) (*UpstreamServerRecord, error) {
	query := `
	SELECT id, name, url, command, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers WHERE name = ?
	`

	row := db.conn.QueryRow(query, name)

	var server UpstreamServerRecord
	var headersJSON, commandJSON string
	var encryptedToken, encryptedPassword, encryptedAPIKey string

	err := row.Scan(
		&server.ID, &server.Name, &server.URL, &commandJSON, &server.Type, &headersJSON,
		&server.Timeout, &server.Enabled, &server.Prefix, &server.Description,
		&server.AuthType, &encryptedToken, &server.AuthUsername, &encryptedPassword, &encryptedAPIKey, &server.AuthHeaderName,
		&server.CreatedAt, &server.UpdatedAt, &server.LastSeen, &server.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream server: %w", err)
	}

	// Unmarshal headers
	if err := json.Unmarshal([]byte(headersJSON), &server.Headers); err != nil {
		server.Headers = make(map[string]string)
	}

	// Unmarshal command
	if err := json.Unmarshal([]byte(commandJSON), &server.Command); err != nil {
		server.Command = []string{}
	}

	// Decrypt sensitive authentication data
	server.AuthToken, err = db.secretManager.Decrypt(encryptedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth token: %w", err)
	}

	server.AuthPassword, err = db.secretManager.Decrypt(encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth password: %w", err)
	}

	server.AuthAPIKey, err = db.secretManager.Decrypt(encryptedAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth API key: %w", err)
	}

	return &server, nil
}

// ListUpstreamServers retrieves all upstream servers
func (db *DB) ListUpstreamServers(enabledOnly bool) ([]*UpstreamServerRecord, error) {
	query := `
	SELECT id, name, url, command, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers
	`

	if enabledOnly {
		query += " WHERE enabled = true"
	}

	query += " ORDER BY name"

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list upstream servers: %w", err)
	}
	defer rows.Close()

	var servers []*UpstreamServerRecord
	for rows.Next() {
		var server UpstreamServerRecord
		var headersJSON, commandJSON string
		var encryptedToken, encryptedPassword, encryptedAPIKey string

		err := rows.Scan(
			&server.ID, &server.Name, &server.URL, &commandJSON, &server.Type, &headersJSON,
			&server.Timeout, &server.Enabled, &server.Prefix, &server.Description,
			&server.AuthType, &encryptedToken, &server.AuthUsername, &encryptedPassword, &encryptedAPIKey, &server.AuthHeaderName,
			&server.CreatedAt, &server.UpdatedAt, &server.LastSeen, &server.Status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan upstream server: %w", err)
		}

		// Parse headers JSON
		if err := json.Unmarshal([]byte(headersJSON), &server.Headers); err != nil {
			server.Headers = make(map[string]string)
		}

		// Parse command JSON
		if err := json.Unmarshal([]byte(commandJSON), &server.Command); err != nil {
			server.Command = []string{}
		}
		servers = append(servers, &server)
	}

	return servers, nil
}

// ListUpstreamServersForConnection lists upstream servers with decrypted auth data for internal connections
func (db *DB) ListUpstreamServersForConnection(enabledOnly bool) ([]*UpstreamServerRecord, error) {
	query := `
	SELECT id, name, url, command, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers
	`

	if enabledOnly {
		query += " WHERE enabled = true"
	}

	query += " ORDER BY name"

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list upstream servers: %w", err)
	}
	defer rows.Close()

	var servers []*UpstreamServerRecord
	for rows.Next() {
		var server UpstreamServerRecord
		var headersJSON, commandJSON string
		var encryptedToken, encryptedPassword, encryptedAPIKey string

		err := rows.Scan(
			&server.ID, &server.Name, &server.URL, &commandJSON, &server.Type, &headersJSON,
			&server.Timeout, &server.Enabled, &server.Prefix, &server.Description,
			&server.AuthType, &encryptedToken, &server.AuthUsername, &encryptedPassword, &encryptedAPIKey, &server.AuthHeaderName,
			&server.CreatedAt, &server.UpdatedAt, &server.LastSeen, &server.Status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan upstream server: %w", err)
		}

		// Parse headers JSON
		if err := json.Unmarshal([]byte(headersJSON), &server.Headers); err != nil {
			server.Headers = make(map[string]string)
		}

		// Parse command JSON
		if err := json.Unmarshal([]byte(commandJSON), &server.Command); err != nil {
			server.Command = []string{}
		}

		// Decrypt sensitive authentication data and keep it for connection use
		server.AuthToken, err = db.secretManager.Decrypt(encryptedToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt auth token: %w", err)
		}

		server.AuthPassword, err = db.secretManager.Decrypt(encryptedPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt auth password: %w", err)
		}

		server.AuthAPIKey, err = db.secretManager.Decrypt(encryptedAPIKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt auth API key: %w", err)
		}

		servers = append(servers, &server)
	}

	return servers, nil
}

// UpdateUpstreamServer updates an existing upstream server
func (db *DB) UpdateUpstreamServer(id int64, updates *UpstreamServerRecord) (*UpstreamServerRecord, error) {
	headersJSON, err := json.Marshal(updates.Headers)
	if err != nil {
		headersJSON = []byte("{}")
	}

	commandJSON, err := json.Marshal(updates.Command)
	if err != nil {
		commandJSON = []byte("[]")
	}

	// Encrypt sensitive authentication data
	encryptedToken, err := db.secretManager.Encrypt(updates.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth token: %w", err)
	}

	encryptedPassword, err := db.secretManager.Encrypt(updates.AuthPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth password: %w", err)
	}

	encryptedAPIKey, err := db.secretManager.Encrypt(updates.AuthAPIKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth API key: %w", err)
	}

	query := `
	UPDATE upstream_servers 
	SET name = ?, url = ?, command = ?, type = ?, headers = ?, timeout = ?, 
		enabled = ?, prefix = ?, description = ?,
		auth_type = ?, auth_token = ?, auth_username = ?, auth_password = ?, auth_api_key = ?, auth_header_name = ?,
		updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`

	_, err = db.conn.Exec(query,
		updates.Name, updates.URL, string(commandJSON), updates.Type, string(headersJSON),
		updates.Timeout, updates.Enabled, updates.Prefix, updates.Description,
		updates.AuthType, encryptedToken, updates.AuthUsername, encryptedPassword, encryptedAPIKey, updates.AuthHeaderName,
		id)
	if err != nil {
		return nil, fmt.Errorf("failed to update upstream server: %w", err)
	}

	return db.GetUpstreamServer(id)
}

// UpdateUpstreamServerStatus updates the status and last seen time of an upstream server
func (db *DB) UpdateUpstreamServerStatus(id int64, status string) error {
	query := `
	UPDATE upstream_servers 
	SET status = ?, last_seen = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`

	_, err := db.conn.Exec(query, status, id)
	return err
}

// DeleteUpstreamServer deletes an upstream server
func (db *DB) DeleteUpstreamServer(id int64) error {
	query := `DELETE FROM upstream_servers WHERE id = ?`
	
	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete upstream server: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("upstream server not found")
	}

	return nil
}

// CreateUser creates a new user
func (db *DB) CreateUser(username, password string) (*UserRecord, error) {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	query := `
	INSERT INTO users (username, password_hash, is_active)
	VALUES (?, ?, ?)
	`

	result, err := db.conn.Exec(query, username, hashedPassword, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetUser(id)
}

// GetUser retrieves a user by ID
func (db *DB) GetUser(id int64) (*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, is_active, created_at, updated_at
	FROM users WHERE id = ?
	`

	row := db.conn.QueryRow(query, id)

	var user UserRecord

	err := row.Scan(
		&user.ID, &user.Username, &user.Password, &user.IsActive,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (db *DB) GetUserByUsername(username string) (*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, is_active, created_at, updated_at
	FROM users WHERE username = ?
	`

	row := db.conn.QueryRow(query, username)

	var user UserRecord

	err := row.Scan(
		&user.ID, &user.Username, &user.Password, &user.IsActive,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// ListUsers retrieves all users
func (db *DB) ListUsers() ([]*UserRecord, error) {
	query := `
	SELECT id, username, password_hash, is_active, created_at, updated_at
	FROM users
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*UserRecord
	for rows.Next() {
		var user UserRecord

		err := rows.Scan(
			&user.ID, &user.Username, &user.Password, &user.IsActive,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		users = append(users, &user)
	}

	return users, nil
}

// UpdateUser updates an existing user
func (db *DB) UpdateUser(id int64, username, password string, isActive bool) (*UserRecord, error) {
	var hashedPassword []byte
	var err error

	// Hash the password if provided
	if password != "" {
		hashedPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
	}

	query := `
	UPDATE users 
	SET username = ?, password_hash = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`

	_, err = db.conn.Exec(query, username, hashedPassword, isActive, id)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return db.GetUser(id)
}

// DeleteUser deletes a user
func (db *DB) DeleteUser(id int64) error {
	query := `DELETE FROM users WHERE id = ?`
	
	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetToken retrieves a token by its value
func (db *DB) GetToken(tokenValue string) (*TokenRecord, error) {
	query := `
	SELECT id, token, user_id, username, description, expires_at, created_at, last_used, is_active
	FROM tokens WHERE token = ?
	`

	row := db.conn.QueryRow(query, tokenValue)

	var token TokenRecord

	err := row.Scan(
		&token.ID, &token.Token, &token.UserID, &token.Username, &token.Description,
		&token.ExpiresAt, &token.CreatedAt, &token.LastUsed, &token.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return &token, nil
}

// UpdateToken updates the last used time and status of a token
func (db *DB) UpdateToken(tokenValue string, isActive bool) error {
	query := `
	UPDATE tokens 
	SET last_used = CURRENT_TIMESTAMP, is_active = ?, updated_at = CURRENT_TIMESTAMP
	WHERE token = ?
	`

	_, err := db.conn.Exec(query, isActive, tokenValue)
	return err
}

// DeleteToken deletes a token
func (db *DB) DeleteToken(tokenValue string) error {
	query := `DELETE FROM tokens WHERE token = ?`
	
	result, err := db.conn.Exec(query, tokenValue)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}

// initializeDefaultUser creates the default admin user if it doesn't exist
func (db *DB) initializeDefaultUser() error {
	// Check if admin user already exists
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing admin user: %w", err)
	}

	if count > 0 {
		return nil // Admin user already exists
	}

	// Hash the default password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash default password: %w", err)
	}

	// Create the admin user
	_, err = db.conn.Exec(`
		INSERT INTO users (username, password_hash, is_active, created_at, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, "admin", string(hashedPassword), true)

	if err != nil {
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	return nil
}

// ValidateUser validates username and password
func (db *DB) ValidateUser(username, password string) (*UserRecord, error) {
	var user UserRecord
	err := db.conn.QueryRow(`
		SELECT id, username, password_hash, is_active, created_at, updated_at
		FROM users
		WHERE username = ? AND is_active = true
	`, username).Scan(&user.ID, &user.Username, &user.Password, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid username or password")
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid username or password")
	}

	// Clear password hash before returning
	user.Password = ""
	return &user, nil
}

// GenerateToken generates a new access token
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateToken creates a new access token for a user
func (db *DB) CreateToken(userID int64, username, description string, expiresAt *time.Time, isInternal bool) (*TokenRecord, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	var tokenRecord TokenRecord
	err = db.conn.QueryRow(`
		INSERT INTO tokens (token, user_id, username, description, expires_at, created_at, is_active, is_internal)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, true, ?)
		RETURNING id, token, user_id, username, description, expires_at, created_at, last_used, is_active, is_internal
	`, token, userID, username, description, expiresAt, isInternal).Scan(
		&tokenRecord.ID, &tokenRecord.Token, &tokenRecord.UserID, &tokenRecord.Username,
		&tokenRecord.Description, &tokenRecord.ExpiresAt, &tokenRecord.CreatedAt,
		&tokenRecord.LastUsed, &tokenRecord.IsActive, &tokenRecord.IsInternal)

	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &tokenRecord, nil
}

// ValidateToken validates an access token and returns user info
func (db *DB) ValidateToken(token string) (*TokenRecord, error) {
	var tokenRecord TokenRecord
	err := db.conn.QueryRow(`
		SELECT id, token, user_id, username, description, expires_at, created_at, last_used, is_active, is_internal
		FROM tokens
		WHERE token = ? AND is_active = true
	`, token).Scan(
		&tokenRecord.ID, &tokenRecord.Token, &tokenRecord.UserID, &tokenRecord.Username,
		&tokenRecord.Description, &tokenRecord.ExpiresAt, &tokenRecord.CreatedAt,
		&tokenRecord.LastUsed, &tokenRecord.IsActive, &tokenRecord.IsInternal)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid token")
		}
		return nil, fmt.Errorf("failed to query token: %w", err)
	}

	// Check if token is expired
	if tokenRecord.ExpiresAt != nil && tokenRecord.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// Update last used timestamp
	_, err = db.conn.Exec("UPDATE tokens SET last_used = CURRENT_TIMESTAMP WHERE id = ?", tokenRecord.ID)
	if err != nil {
		// Log error but don't fail the validation
		// This is a non-critical operation
	}

	return &tokenRecord, nil
}

// ListTokens lists all active non-internal tokens for a user
func (db *DB) ListTokens(userID int64) ([]TokenRecord, error) {
	rows, err := db.conn.Query(`
		SELECT id, token, user_id, username, description, expires_at, created_at, last_used, is_active, is_internal
		FROM tokens
		WHERE user_id = ? AND is_active = true AND is_internal = false
		ORDER BY created_at DESC
	`, userID)

	if err != nil {
		return nil, fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []TokenRecord
	for rows.Next() {
		var token TokenRecord
		err := rows.Scan(
			&token.ID, &token.Token, &token.UserID, &token.Username,
			&token.Description, &token.ExpiresAt, &token.CreatedAt,
			&token.LastUsed, &token.IsActive, &token.IsInternal)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// RevokeToken revokes (deactivates) a token
func (db *DB) RevokeToken(tokenID int64, userID int64) error {
	result, err := db.conn.Exec("UPDATE tokens SET is_active = false WHERE id = ? AND user_id = ?", tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("token not found or not owned by user")
	}

	return nil
}

// ToUpstreamServer converts a database record to types.UpstreamServer
func (r *UpstreamServerRecord) ToUpstreamServer() *types.UpstreamServer {
	upstream := &types.UpstreamServer{
		Name:    r.Name,
		URL:     r.URL,
		Command: r.Command,
		Type:    r.Type,
		Headers: r.Headers,
		Timeout: r.Timeout,
		Enabled: r.Enabled,
		Prefix:  r.Prefix,
	}

	// Add authentication configuration if present
	if r.AuthType != "" {
		upstream.Auth = &types.AuthConfig{
			Type:        r.AuthType,
			BearerToken: r.AuthToken,
			Username:    r.AuthUsername,
			Password:    r.AuthPassword,
			APIKey:      r.AuthAPIKey,
			HeaderName:  r.AuthHeaderName,
		}
	}

	return upstream
}

// FromUpstreamServer creates a database record from types.UpstreamServer
func FromUpstreamServer(server *types.UpstreamServer) *UpstreamServerRecord {
	record := &UpstreamServerRecord{
		Name:    server.Name,
		URL:     server.URL,
		Command: server.Command,
		Type:    server.Type,
		Headers: server.Headers,
		Timeout: server.Timeout,
		Enabled: server.Enabled,
		Prefix:  server.Prefix,
		Status:  "disconnected",
	}

	// Add authentication configuration if present
	if server.Auth != nil {
		record.AuthType = server.Auth.Type
		record.AuthToken = server.Auth.BearerToken
		record.AuthUsername = server.Auth.Username
		record.AuthPassword = server.Auth.Password
		record.AuthAPIKey = server.Auth.APIKey
		record.AuthHeaderName = server.Auth.HeaderName
	}

	return record
}
