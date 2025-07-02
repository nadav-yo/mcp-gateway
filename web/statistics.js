// Statistics Tab JavaScript Module

class StatisticsTab {
    constructor(adminPanel) {
        this.adminPanel = adminPanel;
        this.lastStatsData = null;
        this.lastStatsTabData = null;
    }

    // Load statistics for the server management tab (simplified stats)
    async loadStats() {
        try {
            const response = await this.adminPanel.makeAuthenticatedRequest('/gateway/stats');
            const stats = await response.json();
            
            // Only update DOM if data has changed
            const statsKey = JSON.stringify({
                upstream_servers: stats.upstream_servers || 0,
                connected_servers: stats.connected_servers || 0,
                total_tools: stats.total_tools || 0,
                total_prompts: stats.total_prompts || 0,
                total_resources: stats.total_resources || 0,
                total_blocked_tools: stats.total_blocked_tools || 0
            });
            
            if (this.lastStatsData !== statsKey) {
                // Update server management tab stats
                document.getElementById('totalServers').textContent = stats.upstream_servers || 0;
                document.getElementById('connectedServers').textContent = stats.connected_servers || 0;
                document.getElementById('totalTools').textContent = stats.total_tools || 0;
                document.getElementById('totalPrompts').textContent = stats.total_prompts || 0;
                document.getElementById('totalResources').textContent = stats.total_resources || 0;
                
                this.lastStatsData = statsKey;
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    // Load comprehensive statistics for the dedicated statistics tab
    async loadStatsForTab() {
        try {
            const [statsResponse, infoResponse] = await Promise.all([
                this.adminPanel.makeAuthenticatedRequest('/gateway/stats'),
                this.adminPanel.makeAuthenticatedRequest('/info')
            ]);
            
            const stats = await statsResponse.json();
            const info = await infoResponse.json();
            
            // Only update DOM if data has changed
            const statsTabKey = JSON.stringify({
                upstream_servers: stats.upstream_servers || 0,
                connected_servers: stats.connected_servers || 0,
                total_tools: stats.total_tools || 0,
                total_prompts: stats.total_prompts || 0,
                total_resources: stats.total_resources || 0,
                requests_processed: stats.requests_processed || 0,
                active_tokens: stats.active_tokens || 0,
                total_users: stats.total_users || 0,
                total_blocked_tools: stats.total_blocked_tools || 0,
                total_blocked_prompts: stats.total_blocked_prompts || 0,
                total_blocked_resources: stats.total_blocked_resources || 0,
                servers_by_status: stats.servers_by_status || {},
                servers_by_type: stats.servers_by_type || {},
                auth_methods_count: stats.auth_methods_count || {},
                system_uptime: stats.system_uptime || '',
                last_database_update: stats.last_database_update || '',
                name: info.name || 'MCP Gateway',
                version: info.version || '1.0.0'
            });
            
            if (this.lastStatsTabData !== statsTabKey) {
                // Update core statistics
                document.getElementById('totalServersStats').textContent = stats.upstream_servers || 0;
                document.getElementById('connectedServersStats').textContent = stats.connected_servers || 0;
                document.getElementById('totalToolsStats').textContent = stats.total_tools || 0;
                document.getElementById('totalPromptsStats').textContent = stats.total_prompts || 0;
                document.getElementById('totalResourcesStats').textContent = stats.total_resources || 0;
                document.getElementById('requestsProcessedStats').textContent = stats.requests_processed || 0;
                
                // Update user & security statistics
                document.getElementById('activeTokensStats').textContent = stats.active_tokens || 0;
                document.getElementById('totalUsersStats').textContent = stats.total_users || 0;
                document.getElementById('totalBlockedToolsStats').textContent = stats.total_blocked_tools || 0;
                document.getElementById('totalBlockedPromptsStats').textContent = stats.total_blocked_prompts || 0;
                document.getElementById('totalBlockedResourcesStats').textContent = stats.total_blocked_resources || 0;
                
                // Update dynamic status charts
                this.updateStatusChart('serverStatusStats', stats.servers_by_status || {});
                this.updateStatusChart('serverTypeStats', stats.servers_by_type || {});
                this.updateStatusChart('authMethodsStats', stats.auth_methods_count || {});
                
                // Update gateway information
                document.getElementById('gatewayName').textContent = info.name || 'MCP Gateway';
                document.getElementById('gatewayVersion').textContent = info.version || '1.0.0';
                document.getElementById('systemUptime').textContent = stats.system_uptime || '-';
                document.getElementById('lastDatabaseUpdate').textContent = this.formatTimestamp(stats.last_database_update) || 'Never';
                
                this.lastStatsTabData = statsTabKey;
            }
            
            // Always update timestamp
            document.getElementById('lastUpdated').textContent = new Date().toLocaleString();
            
            // Update last refresh time for stats tab
            this.adminPanel.updateLastRefreshTime();
            
        } catch (error) {
            console.error('Error loading stats for tab:', error);
            // Show error in stats if loading fails
            document.querySelectorAll('#statsContent .stat-number').forEach(el => {
                el.textContent = 'Error';
            });
            document.getElementById('gatewayName').textContent = 'Error loading';
            document.getElementById('gatewayVersion').textContent = 'Error loading';
            document.getElementById('lastUpdated').textContent = 'Error loading';
        }
    }

    // Helper method to update status charts (creates visual representations of data distributions)
    updateStatusChart(containerId, data) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = '';
        
        // If no data, show "No data" message
        if (!data || Object.keys(data).length === 0) {
            container.innerHTML = '<div class="stat-card"><div class="stat-number">-</div><div class="stat-label">No Data</div></div>';
            return;
        }
        
        // Create stat cards for each item in the data
        for (const [key, value] of Object.entries(data)) {
            const card = document.createElement('div');
            card.className = 'stat-card';
            
            const number = document.createElement('div');
            number.className = 'stat-number';
            number.textContent = value;
            
            const label = document.createElement('div');
            label.className = 'stat-label';
            label.textContent = this.formatLabel(key);
            
            card.appendChild(number);
            card.appendChild(label);
            container.appendChild(card);
        }
    }
    
    // Helper method to format labels for better readability
    formatLabel(key) {
        return key.split('_')
                 .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                 .join(' ');
    }
    
    // Helper method to format timestamps
    formatTimestamp(timestamp) {
        if (!timestamp || timestamp === 'Never') {
            return 'Never';
        }
        
        try {
            const date = new Date(timestamp);
            if (isNaN(date.getTime())) {
                return timestamp; // Return as-is if can't parse
            }
            return date.toLocaleString();
        } catch (error) {
            return timestamp; // Return as-is if error
        }
    }

    // Clear cached data
    clearCache() {
        this.lastStatsData = null;
        this.lastStatsTabData = null;
    }
}

// Export the class for use in the main admin panel
window.StatisticsTab = StatisticsTab;
