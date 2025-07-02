package database

import (
	"database/sql"
	"fmt"
	"time"
)

// BlockedResourceRecord represents a blocked resource record in the database
type BlockedResourceRecord struct {
	ID           int64     `json:"id" db:"id"`
	ServerID     int64     `json:"server_id" db:"server_id"`
	Type         string    `json:"type" db:"type"` // "servers" or "curated_servers"
	ResourceName string    `json:"resource_name" db:"resource_name"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// CreateBlockedResource creates a new blocked resource entry
func (db *DB) CreateBlockedResource(blockedResource *BlockedResourceRecord) (*BlockedResourceRecord, error) {
	// Validate type
	if blockedResource.Type != "servers" && blockedResource.Type != "curated_servers" {
		return nil, fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", blockedResource.Type)
	}

	// Validate that the server exists
	exists, err := db.serverExistsForType(blockedResource.ServerID, blockedResource.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to validate server existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("server with ID %d and type %s does not exist", blockedResource.ServerID, blockedResource.Type)
	}

	// Check if this exact combination already exists
	exists, err = db.blockedResourceExists(blockedResource.ServerID, blockedResource.Type, blockedResource.ResourceName)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("resource '%s' is already blocked for server ID %d (type: %s)",
			blockedResource.ResourceName, blockedResource.ServerID, blockedResource.Type)
	}

	query := `
	INSERT INTO blocked_resources (server_id, type, resource_name)
	VALUES (?, ?, ?)
	`

	var result sql.Result
	err = db.retryOnBusy(func() error {
		var execErr error
		result, execErr = db.conn.Exec(query, blockedResource.ServerID, blockedResource.Type, blockedResource.ResourceName)
		return execErr
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to create blocked resource: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return db.GetBlockedResource(id)
}

// GetBlockedResource retrieves a blocked resource by ID
func (db *DB) GetBlockedResource(id int64) (*BlockedResourceRecord, error) {
	query := `
	SELECT id, server_id, type, resource_name, created_at
	FROM blocked_resources WHERE id = ?
	`

	var blockedResource BlockedResourceRecord
	err := db.retryOnBusy(func() error {
		row := db.conn.QueryRow(query, id)
		return row.Scan(
			&blockedResource.ID, &blockedResource.ServerID, &blockedResource.Type,
			&blockedResource.ResourceName, &blockedResource.CreatedAt,
		)
	}, 3)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("blocked resource with ID %d not found", id)
		}
		return nil, fmt.Errorf("failed to get blocked resource: %w", err)
	}

	return &blockedResource, nil
}

// ListBlockedResourcesByServerID retrieves all blocked resources for a specific server
func (db *DB) ListBlockedResourcesByServerID(serverID int64, serverType string) ([]*BlockedResourceRecord, error) {
	// Validate type
	if serverType != "servers" && serverType != "curated_servers" {
		return nil, fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", serverType)
	}

	query := `
	SELECT id, server_id, type, resource_name, created_at
	FROM blocked_resources 
	WHERE server_id = ? AND type = ?
	ORDER BY resource_name ASC
	`

	var blockedResources []*BlockedResourceRecord
	err := db.retryOnBusy(func() error {
		rows, err := db.conn.Query(query, serverID, serverType)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the slice for retry attempts
		blockedResources = nil
		for rows.Next() {
			var blockedResource BlockedResourceRecord
			err := rows.Scan(
				&blockedResource.ID, &blockedResource.ServerID, &blockedResource.Type,
				&blockedResource.ResourceName, &blockedResource.CreatedAt,
			)
			if err != nil {
				return err
			}
			blockedResources = append(blockedResources, &blockedResource)
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list blocked resources: %w", err)
	}

	return blockedResources, nil
}

// ListAllBlockedResources retrieves all blocked resources
func (db *DB) ListAllBlockedResources() ([]*BlockedResourceRecord, error) {
	query := `
	SELECT id, server_id, type, resource_name, created_at
	FROM blocked_resources 
	ORDER BY type ASC, server_id ASC, resource_name ASC
	`

	var blockedResources []*BlockedResourceRecord
	err := db.retryOnBusy(func() error {
		rows, err := db.conn.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the slice for retry attempts
		blockedResources = nil
		for rows.Next() {
			var blockedResource BlockedResourceRecord
			err := rows.Scan(
				&blockedResource.ID, &blockedResource.ServerID, &blockedResource.Type,
				&blockedResource.ResourceName, &blockedResource.CreatedAt,
			)
			if err != nil {
				return err
			}
			blockedResources = append(blockedResources, &blockedResource)
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list all blocked resources: %w", err)
	}

	return blockedResources, nil
}

// DeleteBlockedResource deletes a blocked resource by ID
func (db *DB) DeleteBlockedResource(id int64) error {
	// Check if blocked resource exists
	_, err := db.GetBlockedResource(id)
	if err != nil {
		return err
	}

	query := "DELETE FROM blocked_resources WHERE id = ?"
	err = db.retryOnBusy(func() error {
		_, execErr := db.conn.Exec(query, id)
		return execErr
	}, 3)
	if err != nil {
		return fmt.Errorf("failed to delete blocked resource: %w", err)
	}

	return nil
}

// DeleteBlockedResourceByDetails deletes a blocked resource by server ID, type, and resource name
func (db *DB) DeleteBlockedResourceByDetails(serverID int64, serverType, resourceName string) error {
	// Validate type
	if serverType != "servers" && serverType != "curated_servers" {
		return fmt.Errorf("invalid type '%s', must be 'servers' or 'curated_servers'", serverType)
	}

	query := "DELETE FROM blocked_resources WHERE server_id = ? AND type = ? AND resource_name = ?"
	var result sql.Result
	err := db.retryOnBusy(func() error {
		var execErr error
		result, execErr = db.conn.Exec(query, serverID, serverType, resourceName)
		return execErr
	}, 3)
	if err != nil {
		return fmt.Errorf("failed to delete blocked resource: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("blocked resource not found for server ID %d, type %s, resource name %s",
			serverID, serverType, resourceName)
	}

	return nil
}

// Helper functions

// blockedResourceExists checks if a blocked resource already exists
func (db *DB) blockedResourceExists(serverID int64, serverType, resourceName string) (bool, error) {
	var count int
	var err error

	// Use retry logic for database busy errors
	retryErr := db.retryOnBusy(func() error {
		query := "SELECT COUNT(*) FROM blocked_resources WHERE server_id = ? AND type = ? AND resource_name = ?"
		err = db.conn.QueryRow(query, serverID, serverType, resourceName).Scan(&count)
		return err
	}, 3)

	if retryErr != nil {
		return false, fmt.Errorf("failed to check blocked resource existence: %w", retryErr)
	}
	return count > 0, nil
}

// IsResourceBlocked checks if a specific resource is blocked for a server
func (db *DB) IsResourceBlocked(serverID int64, serverType, resourceName string) (bool, error) {
	var count int
	var err error

	// Use retry logic for database busy errors
	retryErr := db.retryOnBusy(func() error {
		query := "SELECT COUNT(*) FROM blocked_resources WHERE server_id = ? AND type = ? AND resource_name = ?"
		err = db.conn.QueryRow(query, serverID, serverType, resourceName).Scan(&count)
		return err
	}, 3)

	if retryErr != nil {
		return false, fmt.Errorf("failed to check if resource is blocked: %w", retryErr)
	}
	return count > 0, nil
}

// GetBlockedResourcesSet returns a set of blocked resource names for a specific server
func (db *DB) GetBlockedResourcesSet(serverID int64, serverType string) (map[string]bool, error) {
	blockedResources, err := db.ListBlockedResourcesByServerID(serverID, serverType)
	if err != nil {
		return nil, err
	}

	blockedSet := make(map[string]bool)
	for _, resource := range blockedResources {
		blockedSet[resource.ResourceName] = true
	}
	return blockedSet, nil
}
