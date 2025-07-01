package database

import (
	"database/sql"
	"fmt"
	"time"
)

// BlockedToolRecord represents a blocked tool record in the database
type BlockedToolRecord struct {
	ID        int64     `json:"id" db:"id"`
	ServerID  int64     `json:"server_id" db:"server_id"`
	Type      string    `json:"type" db:"type"` // "servers" or "curated_servers"
	ToolName  string    `json:"tool_name" db:"tool_name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CreateBlockedTool creates a new blocked tool entry
func (db *DB) CreateBlockedTool(blockedTool *BlockedToolRecord) (*BlockedToolRecord, error) {
	// Validate type
	if blockedTool.Type != "servers" && blockedTool.Type != "curated_servers" {
		return nil, fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", blockedTool.Type)
	}

	// Validate that the server exists
	exists, err := db.serverExistsForType(blockedTool.ServerID, blockedTool.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to validate server existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("server with ID %d and type %s does not exist", blockedTool.ServerID, blockedTool.Type)
	}

	// Check if this exact combination already exists
	exists, err = db.blockedToolExists(blockedTool.ServerID, blockedTool.Type, blockedTool.ToolName)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("tool '%s' is already blocked for server ID %d (type: %s)",
			blockedTool.ToolName, blockedTool.ServerID, blockedTool.Type)
	}

	query := `
	INSERT INTO blocked_tools (server_id, type, tool_name)
	VALUES (?, ?, ?)
	`

	result, err := db.conn.Exec(query, blockedTool.ServerID, blockedTool.Type, blockedTool.ToolName)
	if err != nil {
		return nil, fmt.Errorf("failed to create blocked tool: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetBlockedTool(id)
}

// GetBlockedTool retrieves a blocked tool by ID
func (db *DB) GetBlockedTool(id int64) (*BlockedToolRecord, error) {
	query := `
	SELECT id, server_id, type, tool_name, created_at
	FROM blocked_tools WHERE id = ?
	`

	row := db.conn.QueryRow(query, id)

	var blockedTool BlockedToolRecord
	err := row.Scan(
		&blockedTool.ID, &blockedTool.ServerID, &blockedTool.Type,
		&blockedTool.ToolName, &blockedTool.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("blocked tool with ID %d not found", id)
		}
		return nil, fmt.Errorf("failed to get blocked tool: %w", err)
	}

	return &blockedTool, nil
}

// ListBlockedToolsByServerID retrieves all blocked tools for a specific server
func (db *DB) ListBlockedToolsByServerID(serverID int64, serverType string) ([]*BlockedToolRecord, error) {
	// Validate type
	if serverType != "servers" && serverType != "curated_servers" {
		return nil, fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", serverType)
	}

	query := `
	SELECT id, server_id, type, tool_name, created_at
	FROM blocked_tools 
	WHERE server_id = ? AND type = ?
	ORDER BY tool_name ASC
	`

	rows, err := db.conn.Query(query, serverID, serverType)
	if err != nil {
		return nil, fmt.Errorf("failed to list blocked tools: %w", err)
	}
	defer rows.Close()

	var blockedTools []*BlockedToolRecord
	for rows.Next() {
		var blockedTool BlockedToolRecord
		err := rows.Scan(
			&blockedTool.ID, &blockedTool.ServerID, &blockedTool.Type,
			&blockedTool.ToolName, &blockedTool.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked tool: %w", err)
		}
		blockedTools = append(blockedTools, &blockedTool)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over blocked tools: %w", err)
	}

	return blockedTools, nil
}

// ListAllBlockedTools retrieves all blocked tools
func (db *DB) ListAllBlockedTools() ([]*BlockedToolRecord, error) {
	query := `
	SELECT id, server_id, type, tool_name, created_at
	FROM blocked_tools 
	ORDER BY type ASC, server_id ASC, tool_name ASC
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all blocked tools: %w", err)
	}
	defer rows.Close()

	var blockedTools []*BlockedToolRecord
	for rows.Next() {
		var blockedTool BlockedToolRecord
		err := rows.Scan(
			&blockedTool.ID, &blockedTool.ServerID, &blockedTool.Type,
			&blockedTool.ToolName, &blockedTool.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked tool: %w", err)
		}
		blockedTools = append(blockedTools, &blockedTool)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over blocked tools: %w", err)
	}

	return blockedTools, nil
}

// DeleteBlockedTool deletes a blocked tool by ID
func (db *DB) DeleteBlockedTool(id int64) error {
	// Check if blocked tool exists
	_, err := db.GetBlockedTool(id)
	if err != nil {
		return err
	}

	query := "DELETE FROM blocked_tools WHERE id = ?"
	_, err = db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete blocked tool: %w", err)
	}

	return nil
}

// DeleteBlockedToolByDetails deletes a blocked tool by server ID, type, and tool name
func (db *DB) DeleteBlockedToolByDetails(serverID int64, serverType, toolName string) error {
	// Validate type
	if serverType != "servers" && serverType != "curated_servers" {
		return fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", serverType)
	}

	query := "DELETE FROM blocked_tools WHERE server_id = ? AND type = ? AND tool_name = ?"
	result, err := db.conn.Exec(query, serverID, serverType, toolName)
	if err != nil {
		return fmt.Errorf("failed to delete blocked tool: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("blocked tool not found for server ID %d, type %s, tool name %s",
			serverID, serverType, toolName)
	}

	return nil
}

// Helper functions

// blockedToolExists checks if a blocked tool already exists
func (db *DB) blockedToolExists(serverID int64, serverType, toolName string) (bool, error) {
	query := "SELECT COUNT(*) FROM blocked_tools WHERE server_id = ? AND type = ? AND tool_name = ?"
	var count int
	err := db.conn.QueryRow(query, serverID, serverType, toolName).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check blocked tool existence: %w", err)
	}
	return count > 0, nil
}

// serverExistsForType checks if a server exists for the given type
func (db *DB) serverExistsForType(serverID int64, serverType string) (bool, error) {
	var query string
	var count int

	switch serverType {
	case "servers":
		query = "SELECT COUNT(*) FROM upstream_servers WHERE id = ?"
	case "curated_servers":
		query = "SELECT COUNT(*) FROM curated_servers WHERE id = ?"
	default:
		return false, fmt.Errorf("invalid server type: %s", serverType)
	}

	err := db.conn.QueryRow(query, serverID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check server existence: %w", err)
	}
	return count > 0, nil
}

// IsToolBlocked checks if a specific tool is blocked for a server
func (db *DB) IsToolBlocked(serverID int64, serverType, toolName string) (bool, error) {
	return db.blockedToolExists(serverID, serverType, toolName)
}

// GetBlockedToolsSet returns a set of blocked tool names for a specific server
func (db *DB) GetBlockedToolsSet(serverID int64, serverType string) (map[string]bool, error) {
	blockedTools, err := db.ListBlockedToolsByServerID(serverID, serverType)
	if err != nil {
		return nil, err
	}

	blockedSet := make(map[string]bool)
	for _, tool := range blockedTools {
		blockedSet[tool.ToolName] = true
	}
	return blockedSet, nil
}
