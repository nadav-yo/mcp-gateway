package database

import (
	"fmt"
)

// GetStatistics returns comprehensive database statistics
func (db *DB) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get active tokens count (excluding internal tokens)
	var activeTokens int
	err := db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE is_active = true AND is_internal = false").Scan(&activeTokens)
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get active tokens count: %w", err)
	}
	stats["active_tokens"] = activeTokens

	// Get total users count
	var totalUsers int
	err = db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&totalUsers)
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get total users count: %w", err)
	}
	stats["total_users"] = totalUsers

	// Get servers by status
	serversByStatus := make(map[string]int)
	err = db.retryOnBusy(func() error {
		rows, err := db.conn.Query("SELECT status, COUNT(*) FROM upstream_servers GROUP BY status")
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the map for retry attempts
		serversByStatus = make(map[string]int)
		for rows.Next() {
			var status string
			var count int
			if err := rows.Scan(&status, &count); err != nil {
				return err
			}
			serversByStatus[status] = count
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get servers by status: %w", err)
	}
	stats["servers_by_status"] = serversByStatus

	// Get servers by type
	serversByType := make(map[string]int)
	err = db.retryOnBusy(func() error {
		rows, err := db.conn.Query("SELECT type, COUNT(*) FROM upstream_servers GROUP BY type")
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the map for retry attempts
		serversByType = make(map[string]int)
		for rows.Next() {
			var serverType string
			var count int
			if err := rows.Scan(&serverType, &count); err != nil {
				return err
			}
			serversByType[serverType] = count
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get servers by type: %w", err)
	}
	stats["servers_by_type"] = serversByType

	// Get auth methods count
	authMethodsCount := make(map[string]int)
	err = db.retryOnBusy(func() error {
		rows, err := db.conn.Query("SELECT CASE WHEN auth_type = '' THEN 'none' ELSE auth_type END as auth_method, COUNT(*) FROM upstream_servers GROUP BY auth_method")
		if err != nil {
			return err
		}
		defer rows.Close()

		// Clear the map for retry attempts
		authMethodsCount = make(map[string]int)
		for rows.Next() {
			var authMethod string
			var count int
			if err := rows.Scan(&authMethod, &count); err != nil {
				return err
			}
			authMethodsCount[authMethod] = count
		}
		return rows.Err()
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth methods count: %w", err)
	}
	stats["auth_methods_count"] = authMethodsCount

	// Get blocked tools count
	var totalBlockedTools int
	err = db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT COUNT(*) FROM blocked_tools").Scan(&totalBlockedTools)
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked tools count: %w", err)
	}
	stats["total_blocked_tools"] = totalBlockedTools

	// Get blocked prompts count
	var totalBlockedPrompts int
	err = db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT COUNT(*) FROM blocked_prompts").Scan(&totalBlockedPrompts)
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked prompts count: %w", err)
	}
	stats["total_blocked_prompts"] = totalBlockedPrompts

	// Get blocked resources count
	var totalBlockedResources int
	err = db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT COUNT(*) FROM blocked_resources").Scan(&totalBlockedResources)
	}, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked resources count: %w", err)
	}
	stats["total_blocked_resources"] = totalBlockedResources

	// Get last database update timestamp
	var lastUpdate string
	err = db.retryOnBusy(func() error {
		return db.conn.QueryRow("SELECT MAX(updated_at) FROM upstream_servers").Scan(&lastUpdate)
	}, 3)
	if err != nil {
		lastUpdate = "Never"
	}
	stats["last_database_update"] = lastUpdate

	return stats, nil
}
