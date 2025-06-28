// Logs Tab JavaScript Module

class LogsTab {
    constructor(adminPanel) {
        this.adminPanel = adminPanel;
        this.currentLogServerId = null;
        this.currentLogFilename = null;
        this.logsAutoRefreshEnabled = false;
        this.logsAutoRefreshTimer = null;
    }

    // Load available server logs
    async loadServerLogs() {
        try {
            const response = await this.adminPanel.makeAuthenticatedRequest('/api/logs');
            const result = await response.json();
            
            if (result.success) {
                this.displayLogsList(result.data.logs);
            } else {
                throw new Error(result.message || result.error || 'Failed to load logs');
            }
        } catch (error) {
            console.error('Error loading logs:', error);
            document.getElementById('logsListContainer').innerHTML = 
                '<div class="error">Error loading logs: ' + error.message + '</div>';
        }
    }

    // Display the list of available logs
    displayLogsList(logs) {
        const container = document.getElementById('logsListContainer');
        
        if (logs.length === 0) {
            container.innerHTML = '<div class="no-logs">No log files found</div>';
            return;
        }
        
        const logsHTML = logs.map(log => `
            <div class="log-item" onclick="adminPanel.logsTab.selectLog(${log.server_id}, '${log.server_name}', '${log.filename}')">
                <div class="log-item-name">${log.server_name}</div>
                <div class="log-item-info">
                    ID: ${log.server_id} | Size: ${this.formatFileSize(log.size)} | 
                    Modified: ${new Date(log.modified).toLocaleString()}
                </div>
            </div>
        `).join('');
        
        container.innerHTML = logsHTML;
    }

    // Load a gateway log file (like request.log)
    async loadLog(filename) {
        // Update active state
        document.querySelectorAll('.log-item').forEach(item => item.classList.remove('active'));
        event.target.closest('.log-item').classList.add('active');
        
        this.currentLogServerId = null; // Clear server ID for generic logs
        this.currentLogFilename = filename;
        
        // Update log viewer header
        document.getElementById('logViewerTitle').textContent = `Gateway Log: ${filename}`;
        document.getElementById('refreshLogBtn').disabled = false;
        document.getElementById('downloadLogBtn').disabled = false;
        
        // Show loading message immediately
        document.getElementById('logContent').innerHTML = `<div class="loading">Loading ${filename}...</div>`;
        
        // Load log content
        await this.loadGenericLogContent(filename);
    }

    // Select and load a server-specific log
    async selectLog(serverId, serverName, filename) {
        // Update active state
        document.querySelectorAll('.log-item').forEach(item => item.classList.remove('active'));
        event.target.closest('.log-item').classList.add('active');
        
        this.currentLogServerId = serverId;
        this.currentLogFilename = filename;
        
        // Update log viewer header
        document.getElementById('logViewerTitle').textContent = `Logs for ${serverName}`;
        document.getElementById('refreshLogBtn').disabled = false;
        document.getElementById('downloadLogBtn').disabled = false;
        
        // Show loading message immediately
        document.getElementById('logContent').innerHTML = `<div class="loading">Loading logs for ${serverName}...</div>`;
        
        // Load log content
        await this.loadLogContent(serverId);
    }

    // Load content for a server-specific log
    async loadLogContent(serverId) {
        const logContent = document.getElementById('logContent');
        const tailCheckbox = document.getElementById('tailLogsCheckbox');
        
        try {
            let url = `/api/upstream-servers/${serverId}/logs`;
            if (tailCheckbox.checked) {
                url += '?tail=true&lines=100';
            }
            
            const response = await this.adminPanel.makeAuthenticatedRequest(url);
            const result = await response.json();
            
            if (result.success) {
                if (result.data.content.trim() === '') {
                    logContent.innerHTML = '<div class="no-log-selected">Log file is empty</div>';
                } else {
                    const lines = result.data.content.split('\n').map(line => 
                        `<div class="log-line">${this.escapeHtml(line)}</div>`
                    ).join('');
                    logContent.innerHTML = lines;
                    
                    // Auto-scroll to bottom
                    logContent.scrollTop = logContent.scrollHeight;
                }
                this.updateLogsLastRefreshTime();
            } else {
                logContent.innerHTML = `<div class="error">Error loading log: ${result.message || result.error || 'Unknown error'}</div>`;
            }
        } catch (error) {
            console.error('Error loading log content:', error);
            logContent.innerHTML = `<div class="error">Error loading log: ${error.message}</div>`;
        }
    }

    // Load content for a gateway log file
    async loadGenericLogContent(filename) {
        const logContent = document.getElementById('logContent');
        const tailCheckbox = document.getElementById('tailLogsCheckbox');
        
        try {
            let url = `/api/logs/${filename}`;
            if (tailCheckbox.checked) {
                url += '?tail=true&lines=100';
            }
            
            const response = await this.adminPanel.makeAuthenticatedRequest(url);
            const result = await response.json();
            
            if (result.success) {
                if (result.data.content.trim() === '') {
                    logContent.innerHTML = '<div class="no-log-content">This log file is empty</div>';
                } else {
                    const lines = result.data.content.split('\n').map(line => 
                        `<div class="log-line">${this.escapeHtml(line)}</div>`
                    ).join('');
                    logContent.innerHTML = lines;
                    
                    // Auto-scroll to bottom
                    logContent.scrollTop = logContent.scrollHeight;
                }
                this.updateLogsLastRefreshTime();
            } else {
                logContent.innerHTML = `<div class="error">Error loading log: ${result.message || result.error || 'Unknown error'}</div>`;
            }
        } catch (error) {
            console.error('Error loading log content:', error);
            logContent.innerHTML = `<div class="error">Error loading log: ${error.message}</div>`;
        }
    }

    // Refresh the currently viewed log
    refreshCurrentLog() {
        if (this.currentLogServerId) {
            // Show loading message immediately
            document.getElementById('logContent').innerHTML = `<div class="loading">Refreshing logs...</div>`;
            this.loadLogContent(this.currentLogServerId);
        } else if (this.currentLogFilename) {
            // Show loading message immediately
            document.getElementById('logContent').innerHTML = `<div class="loading">Refreshing ${this.currentLogFilename}...</div>`;
            this.loadGenericLogContent(this.currentLogFilename);
        }
    }

    // Download the currently viewed log
    async downloadCurrentLog() {
        if (this.currentLogServerId) {
            try {
                const url = `/api/upstream-servers/${this.currentLogServerId}/logs?download=true`;
                const response = await this.adminPanel.makeAuthenticatedRequest(url);
                
                if (response.ok) {
                    const blob = await response.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = downloadUrl;
                    a.download = `server-${this.currentLogServerId}.log`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(downloadUrl);
                } else {
                    alert('Failed to download log file');
                }
            } catch (error) {
                console.error('Error downloading log:', error);
                alert('Error downloading log: ' + error.message);
            }
        } else if (this.currentLogFilename) {
            try {
                const url = `/api/logs/${this.currentLogFilename}?download=true`;
                const response = await this.adminPanel.makeAuthenticatedRequest(url);
                
                if (response.ok) {
                    const blob = await response.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = downloadUrl;
                    a.download = this.currentLogFilename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(downloadUrl);
                } else {
                    alert('Failed to download log file');
                }
            } catch (error) {
                console.error('Error downloading log:', error);
                alert('Error downloading log: ' + error.message);
            }
        }
    }

    // Toggle tail mode (show last 100 lines)
    toggleLogTail() {
        if (this.currentLogServerId) {
            this.loadLogContent(this.currentLogServerId);
        } else if (this.currentLogFilename) {
            this.loadGenericLogContent(this.currentLogFilename);
        }
    }

    // Toggle auto-refresh for logs
    toggleLogsAutoRefresh() {
        const toggle = document.getElementById('logsAutoRefreshToggle');
        this.logsAutoRefreshEnabled = !this.logsAutoRefreshEnabled;
        
        if (this.logsAutoRefreshEnabled) {
            toggle.classList.add('active');
            this.startLogsAutoRefresh();
        } else {
            toggle.classList.remove('active');
            this.stopLogsAutoRefresh();
        }
    }

    // Start auto-refresh timer for logs
    startLogsAutoRefresh() {
        if (this.logsAutoRefreshTimer) {
            clearInterval(this.logsAutoRefreshTimer);
        }
        
        this.logsAutoRefreshTimer = setInterval(() => {
            if (this.currentLogServerId && !document.getElementById('logsTab').classList.contains('hidden')) {
                this.loadLogContent(this.currentLogServerId);
            } else if (this.currentLogFilename && !document.getElementById('logsTab').classList.contains('hidden')) {
                this.loadGenericLogContent(this.currentLogFilename);
            }
        }, 5000); // Refresh every 5 seconds
    }

    // Stop auto-refresh timer for logs
    stopLogsAutoRefresh() {
        if (this.logsAutoRefreshTimer) {
            clearInterval(this.logsAutoRefreshTimer);
            this.logsAutoRefreshTimer = null;
        }
    }

    // Switch to logs tab and load a specific server's logs
    async viewServerLogs(serverId, serverName) {
        // Switch to logs tab
        await this.adminPanel.switchTab('logs');
        
        // Load server logs after a short delay to ensure tab is loaded
        setTimeout(() => {
            this.loadServerLogs().then(() => {
                // Find and select the specific server log
                const logItems = document.querySelectorAll('.log-item');
                logItems.forEach(item => {
                    const nameElement = item.querySelector('.log-item-name');
                    if (nameElement && nameElement.textContent === serverName) {
                        item.click();
                    }
                });
            });
        }, 100);
    }

    // Utility function to format file sizes
    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Utility function to escape HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Update the last refresh time display
    updateLogsLastRefreshTime() {
        const lastUpdateElement = document.getElementById('logsLastUpdateTime');
        if (lastUpdateElement) {
            const now = new Date();
            const timeString = now.toLocaleTimeString();
            lastUpdateElement.textContent = `Last updated: ${timeString}`;
            lastUpdateElement.style.color = '#86868b';
        }
    }

    // Clean up resources when switching away from logs
    cleanup() {
        this.stopLogsAutoRefresh();
    }
}

// Export the class for use in the main admin panel
window.LogsTab = LogsTab;
