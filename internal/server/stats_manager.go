package server

import (
	"fmt"
	"time"

	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

// updateStats updates the gateway statistics
func (s *Server) updateStats() {
	connectedServers := 0
	for _, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			connectedServers++
		}
	}

	// Get total server count from database
	servers, err := s.db.ListUpstreamServers(false)
	totalServers := 0
	if err == nil {
		totalServers = len(servers)
	}

	// Get additional statistics from database
	dbStats, err := s.db.GetStatistics()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get database statistics")
		dbStats = make(map[string]interface{})
	}

	// Calculate uptime
	uptime := time.Since(s.startTime)
	uptimeStr := formatDuration(uptime)

	s.stats = types.GatewayStats{
		UpstreamServers:   totalServers,
		ConnectedServers:  connectedServers,
		TotalTools:        len(s.tools),
		TotalResources:    len(s.resources),
		RequestsProcessed: s.stats.RequestsProcessed, // Keep the existing count
		
		// Additional statistics
		ActiveTokens:       getIntFromStats(dbStats, "active_tokens"),
		TotalUsers:         getIntFromStats(dbStats, "total_users"),
		ServersByStatus:    getMapFromStats(dbStats, "servers_by_status"),
		ServersByType:      getMapFromStats(dbStats, "servers_by_type"),
		AuthMethodsCount:   getMapFromStats(dbStats, "auth_methods_count"),
		SystemUptime:       uptimeStr,
		LastDatabaseUpdate: getStringFromStats(dbStats, "last_database_update"),
	}
}

// Helper functions for extracting data from database statistics
func getIntFromStats(stats map[string]interface{}, key string) int {
	if val, ok := stats[key]; ok {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

func getMapFromStats(stats map[string]interface{}, key string) map[string]int {
	if val, ok := stats[key]; ok {
		if mapVal, ok := val.(map[string]int); ok {
			return mapVal
		}
	}
	return make(map[string]int)
}

func getStringFromStats(stats map[string]interface{}, key string) string {
	if val, ok := stats[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
