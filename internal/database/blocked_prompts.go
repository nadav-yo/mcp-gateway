package database

import (
	"database/sql"
	"fmt"
	"time"
)

// BlockedPromptRecord represents a blocked prompt record in the database
type BlockedPromptRecord struct {
	ID         int64     `json:"id" db:"id"`
	ServerID   int64     `json:"server_id" db:"server_id"`
	Type       string    `json:"type" db:"type"` // "servers" or "curated_servers"
	PromptName string    `json:"prompt_name" db:"prompt_name"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// CreateBlockedPrompt creates a new blocked prompt entry
func (db *DB) CreateBlockedPrompt(blockedPrompt *BlockedPromptRecord) (*BlockedPromptRecord, error) {
	// Validate type
	if blockedPrompt.Type != "servers" && blockedPrompt.Type != "curated_servers" {
		return nil, fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", blockedPrompt.Type)
	}

	// Validate that the server exists
	exists, err := db.serverExistsForType(blockedPrompt.ServerID, blockedPrompt.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to validate server existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("server with ID %d and type %s does not exist", blockedPrompt.ServerID, blockedPrompt.Type)
	}

	// Check if this exact combination already exists
	exists, err = db.blockedPromptExists(blockedPrompt.ServerID, blockedPrompt.Type, blockedPrompt.PromptName)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("prompt '%s' is already blocked for server ID %d (type: %s)",
			blockedPrompt.PromptName, blockedPrompt.ServerID, blockedPrompt.Type)
	}

	query := `
	INSERT INTO blocked_prompts (server_id, type, prompt_name)
	VALUES (?, ?, ?)
	`

	var result sql.Result
	err = db.retryOnBusy(func() error {
		var execErr error
		result, execErr = db.conn.Exec(query, blockedPrompt.ServerID, blockedPrompt.Type, blockedPrompt.PromptName)
		return execErr
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to create blocked prompt: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetBlockedPrompt(id)
}

// GetBlockedPrompt retrieves a blocked prompt by ID
func (db *DB) GetBlockedPrompt(id int64) (*BlockedPromptRecord, error) {
	query := `
	SELECT id, server_id, type, prompt_name, created_at
	FROM blocked_prompts WHERE id = ?
	`

	var blockedPrompt BlockedPromptRecord
	err := db.retryOnBusy(func() error {
		row := db.conn.QueryRow(query, id)
		return row.Scan(
			&blockedPrompt.ID, &blockedPrompt.ServerID, &blockedPrompt.Type,
			&blockedPrompt.PromptName, &blockedPrompt.CreatedAt,
		)
	}, 3)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("blocked prompt with ID %d not found", id)
		}
		return nil, fmt.Errorf("failed to get blocked prompt: %w", err)
	}

	return &blockedPrompt, nil
}

// ListBlockedPromptsByServerID retrieves all blocked prompts for a specific server
func (db *DB) ListBlockedPromptsByServerID(serverID int64, serverType string) ([]*BlockedPromptRecord, error) {
	// Validate type
	if serverType != "servers" && serverType != "curated_servers" {
		return nil, fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", serverType)
	}

	query := `
	SELECT id, server_id, type, prompt_name, created_at
	FROM blocked_prompts 
	WHERE server_id = ? AND type = ?
	ORDER BY prompt_name ASC
	`

	var blockedPrompts []*BlockedPromptRecord
	err := db.retryOnBusy(func() error {
		rows, err := db.conn.Query(query, serverID, serverType)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the slice for retry attempts
		blockedPrompts = nil
		for rows.Next() {
			var blockedPrompt BlockedPromptRecord
			err := rows.Scan(
				&blockedPrompt.ID, &blockedPrompt.ServerID, &blockedPrompt.Type,
				&blockedPrompt.PromptName, &blockedPrompt.CreatedAt,
			)
			if err != nil {
				return err
			}
			blockedPrompts = append(blockedPrompts, &blockedPrompt)
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list blocked prompts: %w", err)
	}

	return blockedPrompts, nil
}

// ListAllBlockedPrompts retrieves all blocked prompts
func (db *DB) ListAllBlockedPrompts() ([]*BlockedPromptRecord, error) {
	query := `
	SELECT id, server_id, type, prompt_name, created_at
	FROM blocked_prompts 
	ORDER BY type ASC, server_id ASC, prompt_name ASC
	`

	var blockedPrompts []*BlockedPromptRecord
	err := db.retryOnBusy(func() error {
		rows, err := db.conn.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the slice for retry attempts
		blockedPrompts = nil
		for rows.Next() {
			var blockedPrompt BlockedPromptRecord
			err := rows.Scan(
				&blockedPrompt.ID, &blockedPrompt.ServerID, &blockedPrompt.Type,
				&blockedPrompt.PromptName, &blockedPrompt.CreatedAt,
			)
			if err != nil {
				return err
			}
			blockedPrompts = append(blockedPrompts, &blockedPrompt)
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list all blocked prompts: %w", err)
	}

	return blockedPrompts, nil
}

// DeleteBlockedPrompt deletes a blocked prompt by ID
func (db *DB) DeleteBlockedPrompt(id int64) error {
	// Check if blocked prompt exists
	_, err := db.GetBlockedPrompt(id)
	if err != nil {
		return err
	}

	query := "DELETE FROM blocked_prompts WHERE id = ?"
	err = db.retryOnBusy(func() error {
		_, execErr := db.conn.Exec(query, id)
		return execErr
	}, 3)
	if err != nil {
		return fmt.Errorf("failed to delete blocked prompt: %w", err)
	}

	return nil
}

// DeleteBlockedPromptByDetails deletes a blocked prompt by server ID, type, and prompt name
func (db *DB) DeleteBlockedPromptByDetails(serverID int64, serverType, promptName string) error {
	// Validate type
	if serverType != "servers" && serverType != "curated_servers" {
		return fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", serverType)
	}

	query := "DELETE FROM blocked_prompts WHERE server_id = ? AND type = ? AND prompt_name = ?"
	var result sql.Result
	err := db.retryOnBusy(func() error {
		var execErr error
		result, execErr = db.conn.Exec(query, serverID, serverType, promptName)
		return execErr
	}, 3)
	if err != nil {
		return fmt.Errorf("failed to delete blocked prompt: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("blocked prompt not found for server ID %d, type %s, prompt name %s",
			serverID, serverType, promptName)
	}

	return nil
}

// Helper functions

// blockedPromptExists checks if a blocked prompt already exists
func (db *DB) blockedPromptExists(serverID int64, serverType, promptName string) (bool, error) {
	var count int
	var err error

	// Use retry logic for database busy errors
	retryErr := db.retryOnBusy(func() error {
		query := "SELECT COUNT(*) FROM blocked_prompts WHERE server_id = ? AND type = ? AND prompt_name = ?"
		err = db.conn.QueryRow(query, serverID, serverType, promptName).Scan(&count)
		return err
	}, 3)

	if retryErr != nil {
		return false, fmt.Errorf("failed to check blocked prompt existence: %w", retryErr)
	}
	return count > 0, nil
}

// IsPromptBlocked checks if a specific prompt is blocked for a server
func (db *DB) IsPromptBlocked(serverID int64, serverType, promptName string) (bool, error) {
	var count int
	var err error

	// Use retry logic for database busy errors
	retryErr := db.retryOnBusy(func() error {
		query := "SELECT COUNT(*) FROM blocked_prompts WHERE server_id = ? AND type = ? AND prompt_name = ?"
		err = db.conn.QueryRow(query, serverID, serverType, promptName).Scan(&count)
		return err
	}, 3)

	if retryErr != nil {
		return false, fmt.Errorf("failed to check if prompt is blocked: %w", retryErr)
	}
	return count > 0, nil
}

// GetBlockedPromptsSet returns a set of blocked prompt names for a specific server
func (db *DB) GetBlockedPromptsSet(serverID int64, serverType string) (map[string]bool, error) {
	blockedPrompts, err := db.ListBlockedPromptsByServerID(serverID, serverType)
	if err != nil {
		return nil, err
	}

	blockedSet := make(map[string]bool)
	for _, prompt := range blockedPrompts {
		blockedSet[prompt.PromptName] = true
	}
	return blockedSet, nil
}
