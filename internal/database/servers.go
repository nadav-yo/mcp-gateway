package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

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

// CreateUpstreamServer creates a new upstream server
func (db *DB) CreateUpstreamServer(server *UpstreamServerRecord) (*UpstreamServerRecord, error) {
	// Check if server name already exists
	exists, err := db.serverNameExists(server.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrServerAlreadyExists{ServerName: server.Name}
	}

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
		if err == sql.ErrNoRows {
			return nil, ErrServerNotFound{ServerID: id}
		}
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
		if err == sql.ErrNoRows {
			return nil, ErrServerNotFound{ServerID: 0} // We don't have the ID in this case
		}
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

	var args []interface{}
	if enabledOnly {
		query += " WHERE enabled = ?"
		args = append(args, true)
	}

	query += " ORDER BY name"

	rows, err := db.conn.Query(query, args...)
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
			&server.CreatedAt, &server.UpdatedAt, &server.LastSeen, &server.Status,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan upstream server: %w", err)
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

		servers = append(servers, &server)
	}

	return servers, nil
}

// ListUpstreamServersForConnection retrieves upstream servers without decrypting sensitive data
func (db *DB) ListUpstreamServersForConnection(enabledOnly bool) ([]*UpstreamServerRecord, error) {
	query := `
	SELECT id, name, url, command, type, headers, timeout, enabled, prefix, description,
		   auth_type, auth_token, auth_username, auth_password, auth_api_key, auth_header_name,
		   created_at, updated_at, last_seen, status
	FROM upstream_servers
	`

	var args []interface{}
	if enabledOnly {
		query += " WHERE enabled = ?"
		args = append(args, true)
	}

	query += " ORDER BY name"

	rows, err := db.conn.Query(query, args...)
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
			&server.CreatedAt, &server.UpdatedAt, &server.LastSeen, &server.Status,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan upstream server: %w", err)
		}

		// Unmarshal headers
		if err := json.Unmarshal([]byte(headersJSON), &server.Headers); err != nil {
			server.Headers = make(map[string]string)
		}

		// Unmarshal command
		if err := json.Unmarshal([]byte(commandJSON), &server.Command); err != nil {
			server.Command = []string{}
		}

		// Decrypt sensitive authentication data only if needed
		if server.AuthType != "" {
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
		}

		servers = append(servers, &server)
	}

	return servers, nil
}

// UpdateUpstreamServer updates an existing upstream server
func (db *DB) UpdateUpstreamServer(id int64, updates *UpstreamServerRecord) (*UpstreamServerRecord, error) {
	// Check if server name already exists (excluding current server)
	exists, err := db.serverNameExistsExcludingID(updates.Name, id)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrServerAlreadyExists{ServerName: updates.Name}
	}

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
	UPDATE upstream_servers SET
		name = ?, url = ?, command = ?, type = ?, headers = ?, timeout = ?, enabled = ?, prefix = ?, description = ?,
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

// UpdateUpstreamServerStatus updates the status and last_seen timestamp of an upstream server
func (db *DB) UpdateUpstreamServerStatus(id int64, status string) error {
	err := db.retryOnBusy(func() error {
		query := `
		UPDATE upstream_servers SET
			status = ?,
			last_seen = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
		`

		_, err := db.conn.Exec(query, status, id)
		return err
	}, 5)

	if err != nil {
		return fmt.Errorf("failed to update upstream server status: %w", err)
	}

	return nil
}

// DeleteUpstreamServer deletes an upstream server
func (db *DB) DeleteUpstreamServer(id int64) error {
	// First check if the server exists
	var exists bool
	err := db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM upstream_servers WHERE id = ?)", id).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if upstream server exists: %w", err)
	}

	if !exists {
		return ErrServerNotFound{ServerID: id}
	}

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
		return ErrServerNotFound{ServerID: id}
	}

	return nil
}

// serverNameExists checks if a server with the given name already exists
func (db *DB) serverNameExists(name string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM upstream_servers WHERE name = ?)"
	err := db.conn.QueryRow(query, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if server name exists: %w", err)
	}
	return exists, nil
}

// serverNameExistsExcludingID checks if a server with the given name exists, excluding a specific ID
func (db *DB) serverNameExistsExcludingID(name string, excludeID int64) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM upstream_servers WHERE name = ? AND id != ?)"
	err := db.conn.QueryRow(query, name, excludeID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if server name exists: %w", err)
	}
	return exists, nil
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
