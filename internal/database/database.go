package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
	"github.com/nadav-yo/mcp-gateway/pkg/types"
	"github.com/nadav-yo/mcp-gateway/internal/secrets"
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
		url TEXT NOT NULL,
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
		status TEXT DEFAULT 'disconnected' CHECK(status IN ('connected', 'disconnected', 'error'))
	);

	CREATE INDEX IF NOT EXISTS idx_upstream_servers_name ON upstream_servers(name);
	CREATE INDEX IF NOT EXISTS idx_upstream_servers_enabled ON upstream_servers(enabled);
	CREATE INDEX IF NOT EXISTS idx_upstream_servers_status ON upstream_servers(status);
	`

	_, err := db.conn.Exec(query)
	return err
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
	INSERT INTO upstream_servers (name, url, type, headers, timeout, enabled, prefix, description,
								  auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query,
		server.Name, server.URL, server.Type, string(headersJSON),
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
	SELECT id, name, url, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers WHERE id = ?
	`

	row := db.conn.QueryRow(query, id)

	var server UpstreamServerRecord
	var headersJSON string
	var encryptedToken, encryptedPassword, encryptedAPIKey string

	err := row.Scan(
		&server.ID, &server.Name, &server.URL, &server.Type, &headersJSON,
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
	SELECT id, name, url, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers WHERE name = ?
	`

	row := db.conn.QueryRow(query, name)

	var server UpstreamServerRecord
	var headersJSON string
	var encryptedToken, encryptedPassword, encryptedAPIKey string

	err := row.Scan(
		&server.ID, &server.Name, &server.URL, &server.Type, &headersJSON,
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
	SELECT id, name, url, type, headers, timeout, enabled, prefix, description,
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
		var headersJSON string
		var encryptedToken, encryptedPassword, encryptedAPIKey string

		err := rows.Scan(
			&server.ID, &server.Name, &server.URL, &server.Type, &headersJSON,
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

		// For security, don't return decrypted secrets in list operations
		// The secrets will be available when getting individual servers
		server.AuthToken = ""
		server.AuthPassword = ""
		server.AuthAPIKey = ""

		servers = append(servers, &server)
	}

	return servers, nil
}

// ListUpstreamServersForConnection lists upstream servers with decrypted auth data for internal connections
func (db *DB) ListUpstreamServersForConnection(enabledOnly bool) ([]*UpstreamServerRecord, error) {
	query := `
	SELECT id, name, url, type, headers, timeout, enabled, prefix, description,
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
		var headersJSON string
		var encryptedToken, encryptedPassword, encryptedAPIKey string

		err := rows.Scan(
			&server.ID, &server.Name, &server.URL, &server.Type, &headersJSON,
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
	SET name = ?, url = ?, type = ?, headers = ?, timeout = ?, 
		enabled = ?, prefix = ?, description = ?,
		auth_type = ?, auth_token = ?, auth_username = ?, auth_password = ?, auth_api_key = ?, auth_header_name = ?,
		updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`

	_, err = db.conn.Exec(query,
		updates.Name, updates.URL, updates.Type, string(headersJSON),
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

// ToUpstreamServer converts a database record to types.UpstreamServer
func (r *UpstreamServerRecord) ToUpstreamServer() *types.UpstreamServer {
	upstream := &types.UpstreamServer{
		Name:    r.Name,
		URL:     r.URL,
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
