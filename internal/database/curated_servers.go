package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CuratedServerRecord represents a curated server record in the database
type CuratedServerRecord struct {
	ID          int64     `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Type        string    `json:"type" db:"type"`
	URL         string    `json:"url" db:"url"`
	Command     string    `json:"command" db:"command"`
	Args        []string  `json:"args" db:"args"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// CreateCuratedServer creates a new curated server
func (db *DB) CreateCuratedServer(server *CuratedServerRecord) (*CuratedServerRecord, error) {
	// Check if server name already exists
	exists, err := db.curatedServerNameExists(server.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("curated server with name '%s' already exists", server.Name)
	}

	argsJSON, err := json.Marshal(server.Args)
	if err != nil {
		argsJSON = []byte("[]")
	}

	query := `
	INSERT INTO curated_servers (name, type, url, command, args, description)
	VALUES (?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query,
		server.Name, server.Type, server.URL, server.Command, string(argsJSON), server.Description)
	if err != nil {
		return nil, fmt.Errorf("failed to create curated server: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetCuratedServer(id)
}

// GetCuratedServer retrieves a curated server by ID
func (db *DB) GetCuratedServer(id int64) (*CuratedServerRecord, error) {
	query := `
	SELECT id, name, type, url, command, args, description, created_at, updated_at
	FROM curated_servers WHERE id = ?
	`

	row := db.conn.QueryRow(query, id)

	var server CuratedServerRecord
	var argsJSON string

	err := row.Scan(
		&server.ID, &server.Name, &server.Type, &server.URL, 
		&server.Command, &argsJSON, &server.Description,
		&server.CreatedAt, &server.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("curated server with ID %d not found", id)
		}
		return nil, fmt.Errorf("failed to get curated server: %w", err)
	}

	// Unmarshal args
	if err := json.Unmarshal([]byte(argsJSON), &server.Args); err != nil {
		server.Args = []string{}
	}

	return &server, nil
}

// GetCuratedServerByName retrieves a curated server by name
func (db *DB) GetCuratedServerByName(name string) (*CuratedServerRecord, error) {
	query := `
	SELECT id, name, type, url, command, args, description, created_at, updated_at
	FROM curated_servers WHERE name = ?
	`

	row := db.conn.QueryRow(query, name)

	var server CuratedServerRecord
	var argsJSON string

	err := row.Scan(
		&server.ID, &server.Name, &server.Type, &server.URL,
		&server.Command, &argsJSON, &server.Description,
		&server.CreatedAt, &server.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("curated server with name '%s' not found", name)
		}
		return nil, fmt.Errorf("failed to get curated server: %w", err)
	}

	// Unmarshal args
	if err := json.Unmarshal([]byte(argsJSON), &server.Args); err != nil {
		server.Args = []string{}
	}

	return &server, nil
}

// ListCuratedServers lists all curated servers
func (db *DB) ListCuratedServers() ([]*CuratedServerRecord, error) {
	query := `
	SELECT id, name, type, url, command, args, description, created_at, updated_at
	FROM curated_servers ORDER BY name
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list curated servers: %w", err)
	}
	defer rows.Close()

	var servers []*CuratedServerRecord
	for rows.Next() {
		var server CuratedServerRecord
		var argsJSON string

		err := rows.Scan(
			&server.ID, &server.Name, &server.Type, &server.URL,
			&server.Command, &argsJSON, &server.Description,
			&server.CreatedAt, &server.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan curated server: %w", err)
		}

		// Unmarshal args
		if err := json.Unmarshal([]byte(argsJSON), &server.Args); err != nil {
			server.Args = []string{}
		}

		servers = append(servers, &server)
	}

	return servers, nil
}

// UpdateCuratedServer updates an existing curated server
func (db *DB) UpdateCuratedServer(id int64, updates *CuratedServerRecord) (*CuratedServerRecord, error) {
	// Check if server exists
	existing, err := db.GetCuratedServer(id)
	if err != nil {
		return nil, err
	}

	// Check if name already exists (if name is being changed)
	if updates.Name != "" && updates.Name != existing.Name {
		exists, err := db.curatedServerNameExists(updates.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("curated server with name '%s' already exists", updates.Name)
		}
	}

	// Build update query dynamically
	setParts := []string{"updated_at = CURRENT_TIMESTAMP"}
	args := []interface{}{}

	if updates.Name != "" {
		setParts = append(setParts, "name = ?")
		args = append(args, updates.Name)
	}
	if updates.Type != "" {
		setParts = append(setParts, "type = ?")
		args = append(args, updates.Type)
	}
	if updates.URL != "" {
		setParts = append(setParts, "url = ?")
		args = append(args, updates.URL)
	}
	if updates.Command != "" {
		setParts = append(setParts, "command = ?")
		args = append(args, updates.Command)
	}
	if updates.Args != nil {
		argsJSON, err := json.Marshal(updates.Args)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal args: %w", err)
		}
		setParts = append(setParts, "args = ?")
		args = append(args, string(argsJSON))
	}
	if updates.Description != "" {
		setParts = append(setParts, "description = ?")
		args = append(args, updates.Description)
	}

	if len(setParts) == 1 { // Only updated_at, no actual changes
		return existing, nil
	}

	// Build the SET clause properly using strings.Join
	setClause := strings.Join(setParts, ", ")
	query := fmt.Sprintf("UPDATE curated_servers SET %s WHERE id = ?", setClause)
	
	args = append(args, id)

	_, err = db.conn.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update curated server: %w", err)
	}

	return db.GetCuratedServer(id)
}

// DeleteCuratedServer deletes a curated server
func (db *DB) DeleteCuratedServer(id int64) error {
	// Check if server exists
	_, err := db.GetCuratedServer(id)
	if err != nil {
		return err
	}

	query := "DELETE FROM curated_servers WHERE id = ?"
	_, err = db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete curated server: %w", err)
	}

	return nil
}

// curatedServerNameExists checks if a curated server name already exists
func (db *DB) curatedServerNameExists(name string) (bool, error) {
	query := "SELECT COUNT(*) FROM curated_servers WHERE name = ?"
	var count int
	err := db.conn.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check curated server name: %w", err)
	}
	return count > 0, nil
}
