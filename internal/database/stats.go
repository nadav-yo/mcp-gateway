package database

import (
	"fmt"
)

// GetStatistics returns comprehensive database statistics
func (db *DB) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get active tokens count (excluding internal tokens)
	var activeTokens int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM tokens WHERE is_active = true AND is_internal = false").Scan(&activeTokens)
	if err != nil {
		return nil, fmt.Errorf("failed to get active tokens count: %w", err)
	}
	stats["active_tokens"] = activeTokens

	// Get total users count
	var totalUsers int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE is_active = true").Scan(&totalUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get total users count: %w", err)
	}
	stats["total_users"] = totalUsers

	// Get servers by status
	serversByStatus := make(map[string]int)
	rows, err := db.conn.Query("SELECT status, COUNT(*) FROM upstream_servers GROUP BY status")
	if err != nil {
		return nil, fmt.Errorf("failed to get servers by status: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan server status: %w", err)
		}
		serversByStatus[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate server status rows: %w", err)
	}
	stats["servers_by_status"] = serversByStatus

	// Get servers by type
	serversByType := make(map[string]int)
	rows, err = db.conn.Query("SELECT type, COUNT(*) FROM upstream_servers GROUP BY type")
	if err != nil {
		return nil, fmt.Errorf("failed to get servers by type: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var serverType string
		var count int
		if err := rows.Scan(&serverType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan server type: %w", err)
		}
		serversByType[serverType] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate server type rows: %w", err)
	}
	stats["servers_by_type"] = serversByType

	// Get auth methods count
	authMethodsCount := make(map[string]int)
	rows, err = db.conn.Query("SELECT CASE WHEN auth_type = '' THEN 'none' ELSE auth_type END as auth_method, COUNT(*) FROM upstream_servers GROUP BY auth_method")
	if err != nil {
		return nil, fmt.Errorf("failed to get auth methods count: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var authMethod string
		var count int
		if err := rows.Scan(&authMethod, &count); err != nil {
			return nil, fmt.Errorf("failed to scan auth method: %w", err)
		}
		authMethodsCount[authMethod] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate auth method rows: %w", err)
	}
	stats["auth_methods_count"] = authMethodsCount

	// Get blocked tools count
	var totalBlockedTools int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM blocked_tools").Scan(&totalBlockedTools)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked tools count: %w", err)
	}
	stats["total_blocked_tools"] = totalBlockedTools

	// Get blocked prompts count
	var totalBlockedPrompts int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM blocked_prompts").Scan(&totalBlockedPrompts)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked prompts count: %w", err)
	}
	stats["total_blocked_prompts"] = totalBlockedPrompts

	// Get blocked resources count
	var totalBlockedResources int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM blocked_resources").Scan(&totalBlockedResources)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked resources count: %w", err)
	}
	stats["total_blocked_resources"] = totalBlockedResources

	// Get last database update timestamp
	var lastUpdate string
	err = db.conn.QueryRow("SELECT MAX(updated_at) FROM upstream_servers").Scan(&lastUpdate)
	if err != nil {
		lastUpdate = "Never"
	}
	stats["last_database_update"] = lastUpdate

	return stats, nil
}
