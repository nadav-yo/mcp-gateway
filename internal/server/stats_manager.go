package server

import (
	"fmt"
	"time"

	"github.com/nadav-yo/mcp-gateway/pkg/types"
)

// updateStats updates the gateway statistics
func (s *Server) updateStats() {

	// Get total server count from database
	servers, err := s.db.ListUpstreamServers(false)
	totalServers := 0
	if err == nil {
		totalServers = len(servers)
	}
	s.logger.Debug().Int("total_servers", totalServers).Msg("Retrieved total servers from database")

	// Get connected servers count
	connectedServers := 0
	for _, mcpClient := range s.clients {
		if mcpClient.IsConnected() {
			connectedServers++
		}
	}
	s.logger.Debug().Int("connected_servers", connectedServers).Msg("Counted connected servers")

	// Get additional statistics from database
	dbStats, err := s.db.GetStatistics()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get database statistics")
		dbStats = make(map[string]interface{})
	}
	s.logger.Debug().Msg("Retrieved database statistics")

	// Calculate uptime
	uptime := time.Since(s.startTime)
	uptimeStr := formatDuration(uptime)

	// Calculate available tools (excluding blocked tools)
	// DEADLOCK FIX: First, get a copy of tools to avoid holding the lock during blocked tool checks
	// This prevents deadlock when isToolBlocked() triggers cache refresh that also needs the mutex
	var toolNames []string
	var promptNames []string
	var resourceNames []string
	func() {
		s.mu.RLock()
		defer s.mu.RUnlock()

		toolNames = make([]string, 0, len(s.tools))
		for toolName := range s.tools {
			toolNames = append(toolNames, toolName)
		}

		promptNames = make([]string, 0, len(s.prompts))
		for promptName := range s.prompts {
			promptNames = append(promptNames, promptName)
		}

		resourceNames = make([]string, 0, len(s.resources))
		for resourceName := range s.resources {
			resourceNames = append(resourceNames, resourceName)
		}
	}()

	// Now check blocked status without holding any mutex
	totalAvailableTools := 0
	for _, toolName := range toolNames {
		if !s.isToolBlocked(toolName) {
			totalAvailableTools++
		}
	}
	s.logger.Debug().Int("total_available_tools", totalAvailableTools).Msg("Calculated available tools")

	// Calculate available prompts (excluding blocked prompts)
	totalAvailablePrompts := 0
	for _, promptName := range promptNames {
		if !s.isPromptBlocked(promptName) {
			totalAvailablePrompts++
		}
	}
	s.logger.Debug().Int("total_available_prompts", totalAvailablePrompts).Msg("Calculated available prompts")

	// Calculate available resources (excluding blocked resources)
	totalAvailableResources := 0
	for _, resourceName := range resourceNames {
		if !s.isResourceBlocked(resourceName) {
			totalAvailableResources++
		}
	}
	s.logger.Debug().Int("total_available_resources", totalAvailableResources).Msg("Calculated available resources")

	s.stats = types.GatewayStats{
		UpstreamServers:   totalServers,
		ConnectedServers:  connectedServers,
		TotalTools:        totalAvailableTools,       // Now reflects only available (non-blocked) tools
		TotalResources:    totalAvailableResources,   // Now reflects only available (non-blocked) resources
		TotalPrompts:      totalAvailablePrompts,     // Now reflects only available (non-blocked) prompts
		RequestsProcessed: s.stats.RequestsProcessed, // Keep the existing count

		// Additional statistics
		ActiveTokens:          getIntFromStats(dbStats, "active_tokens"),
		TotalUsers:            getIntFromStats(dbStats, "total_users"),
		TotalBlockedTools:     getIntFromStats(dbStats, "total_blocked_tools"),
		TotalBlockedPrompts:   getIntFromStats(dbStats, "total_blocked_prompts"),
		TotalBlockedResources: getIntFromStats(dbStats, "total_blocked_resources"),
		ServersByStatus:       getMapFromStats(dbStats, "servers_by_status"),
		ServersByType:         getMapFromStats(dbStats, "servers_by_type"),
		AuthMethodsCount:      getMapFromStats(dbStats, "auth_methods_count"),
		SystemUptime:          uptimeStr,
		LastDatabaseUpdate:    getStringFromStats(dbStats, "last_database_update"),
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
