// MCP Gateway Admin Panel JavaScript

class AdminPanel {
    constructor() {
        // Check if auth is enabled (injected by server)
        this.authEnabled = window.AUTH_ENABLED || false;
        this.token = null;
        this.user = null;
        this.currentEditingId = null;
        
        // Auto-refresh configuration
        this.autoRefreshEnabled = true;
        this.autoRefreshInterval = 5000; // 5 seconds
        this.autoRefreshTimer = null;
        this.lastRefreshTime = 0;
        this.isRefreshing = false;
        
        // Cache for preventing unnecessary DOM updates
        this.lastServersData = null;
        
        // Loading indicator state
        this.refreshIndicatorTimeout = null;
        
        if (this.authEnabled) {
            this.token = localStorage.getItem('mcp_token');
        }
        
        // Initialize statistics tab
        this.statisticsTab = new StatisticsTab(this);
        
        this.init();
    }

    async init() {
        // Load statistics HTML
        await this.loadStatisticsHTML();
        
        if (this.authEnabled) {
            this.setupAuthUI();
            if (this.token) {
                await this.checkAuth();
            } else {
                this.showLogin();
            }
        } else {
            this.showAdminPanel(false);
        }
        
        this.setupEventListeners();
        await this.loadInitialData();
        this.startAutoRefresh();
    }

    async loadStatisticsHTML() {
        try {
            const response = await fetch('/static/statistics.html');
            const html = await response.text();
            document.getElementById('statisticsTabPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading statistics HTML:', error);
        }
    }
    
    setupAuthUI() {
        // Show auth-specific elements
        document.getElementById('logoutBtn').classList.remove('hidden');
        document.getElementById('userInfo').classList.remove('hidden');
        
        // Hide description for auth mode
        document.getElementById('adminDescription').style.display = 'none';
    }

    async checkAuth() {
        try {
            const response = await this.makeAuthenticatedRequest('/auth/tokens');
            if (response.ok) {
                this.showAdminPanel(true);
                if (this.authEnabled) {
                    await this.loadTokens();
                }
            } else {
                this.logout();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            this.logout();
        }
    }

    async login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.token;
                this.user = data.user;
                localStorage.setItem('mcp_token', this.token);
                this.showAdminPanel(true);
                await this.loadTokens();
                await this.loadInitialData();
            } else {
                const error = await response.text();
                this.showError('loginError', error);
            }
        } catch (error) {
            this.showError('loginError', 'Login failed: ' + error.message);
        }
    }

    logout() {
        this.stopAutoRefresh();
        this.token = null;
        this.user = null;
        localStorage.removeItem('mcp_token');
        this.showLogin();
    }

    showLogin() {
        document.getElementById('loginContainer').classList.remove('hidden');
        document.getElementById('adminPanel').classList.add('hidden');
    }

    showAdminPanel(isAuthenticated) {
        document.getElementById('loginContainer').classList.add('hidden');
        document.getElementById('adminPanel').classList.remove('hidden');
        
        if (isAuthenticated && this.user) {
            document.getElementById('userInfo').textContent = `Logged in as: ${this.user.username}`;
        }
        
        // Show appropriate tabs and content
        if (this.authEnabled) {
            document.getElementById('authTabs').classList.remove('hidden');
            document.getElementById('noAuthTabs').classList.add('hidden');
            // Set servers tab as active by default
            document.querySelector('#authTabs [data-tab="servers"]').classList.add('active');
        } else {
            document.getElementById('noAuthTabs').classList.remove('hidden');
            document.getElementById('authTabs').classList.add('hidden');
            // Set servers tab as active by default
            document.querySelector('#noAuthTabs [data-tab="servers"]').classList.add('active');
        }
        
        // Show servers tab content by default
        document.getElementById('serversTab').classList.remove('hidden');
        
        // Initialize auto-refresh UI
        this.updateAutoRefreshUI();
    }

    setupEventListeners() {
        // Login form
        if (this.authEnabled) {
            document.getElementById('loginForm').addEventListener('submit', (e) => {
                e.preventDefault();
                this.login();
            });
            
            document.getElementById('logoutBtn').addEventListener('click', () => {
                this.logout();
            });
            
            // Tab switching
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', (e) => {
                    this.switchTab(e.target.dataset.tab);
                });
            });
            
            // Token form
            document.getElementById('createTokenForm').addEventListener('submit', (e) => {
                e.preventDefault();
                this.createToken();
            });
        }
    }

    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Show/hide content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.add('hidden');
        });
        
        // Stop logs auto-refresh when leaving logs tab
        if (tabName !== 'logs') {
            stopLogsAutoRefresh();
        }
        
        // Show the appropriate tab content
        switch(tabName) {
            case 'tokens':
                document.getElementById('tokensTab').classList.remove('hidden');
                break;
            case 'servers':
                document.getElementById('serversTab').classList.remove('hidden');
                break;
            case 'stats':
                document.getElementById('statsTab').classList.remove('hidden');
                // Load stats when switching to stats tab
                this.statisticsTab.loadStatsForTab();
                break;
            case 'logs':
                document.getElementById('logsTab').classList.remove('hidden');
                // Load logs when switching to logs tab
                loadServerLogs();
                break;
        }
    }

    async loadInitialData() {
        await this.statisticsTab.loadStats();
        await this.loadServers();
    }

    // Auto-refresh functionality
    startAutoRefresh() {
        if (this.autoRefreshTimer) {
            clearInterval(this.autoRefreshTimer);
        }
        
        this.autoRefreshTimer = setInterval(() => {
            if (this.autoRefreshEnabled && !this.isRefreshing) {
                this.performAutoRefresh();
            }
        }, this.autoRefreshInterval);
        
        console.log(`Auto-refresh started (${this.autoRefreshInterval}ms interval)`);
    }
    
    stopAutoRefresh() {
        if (this.autoRefreshTimer) {
            clearInterval(this.autoRefreshTimer);
            this.autoRefreshTimer = null;
            console.log('Auto-refresh stopped');
        }
    }
    
    async performAutoRefresh() {
        const now = Date.now();
        // Avoid too frequent refreshes
        if (now - this.lastRefreshTime < 1000) {
            return;
        }
        
        this.isRefreshing = true;
        this.lastRefreshTime = now;
        
        // Add subtle loading indicator
        this.showRefreshingIndicator(true);
        
        try {
            // Only refresh if we're looking at the servers tab or stats tab
            const currentTab = this.getCurrentActiveTab();
            
            if (currentTab === 'servers' || !currentTab) {
                // Always refresh servers data as it's the main tab
                await Promise.all([
                    this.statisticsTab.loadStats(),
                    this.loadServers()
                ]);
            } else if (currentTab === 'stats') {
                // Refresh stats tab data
                await this.statisticsTab.loadStatsForTab();
            }
            // Don't auto-refresh tokens tab for security reasons
            
        } catch (error) {
            console.error('Auto-refresh failed:', error);
            // Don't show error to user for auto-refresh failures
        } finally {
            this.isRefreshing = false;
            this.showRefreshingIndicator(false);
        }
    }
    
    getCurrentActiveTab() {
        const activeTab = document.querySelector('.tab.active');
        return activeTab ? activeTab.dataset.tab : null;
    }
    
    toggleAutoRefresh() {
        this.autoRefreshEnabled = !this.autoRefreshEnabled;
        this.updateAutoRefreshUI();
        console.log(`Auto-refresh ${this.autoRefreshEnabled ? 'enabled' : 'disabled'}`);
    }
    
    updateAutoRefreshUI() {
        const toggle = document.getElementById('autoRefreshToggle');
        if (toggle) {
            if (this.autoRefreshEnabled) {
                toggle.classList.add('active');
            } else {
                toggle.classList.remove('active');
            }
        }
    }

    async makeAuthenticatedRequest(url, options = {}) {
        if (this.authEnabled && this.token) {
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${this.token}`
            };
        }
        return fetch(url, options);
    }

    // Token management methods (auth only)
    async loadTokens() {
        if (!this.authEnabled) return;
        
        try {
            // Add cache busting parameter
            const response = await this.makeAuthenticatedRequest(`/auth/tokens?_=${new Date().getTime()}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${await response.text()}`);
            }
            const tokens = await response.json();
            this.renderTokens(tokens);
        } catch (error) {
            console.error('Error loading tokens:', error);
            this.showError('tokenError', 'Failed to load tokens: ' + error.message);
        }
    }

    renderTokens(tokens) {
        const tokensList = document.getElementById('tokensList');
        
        if (!tokens || tokens.length === 0) {
            tokensList.innerHTML = '<div class="loading">No API tokens found. Create tokens here for external access to the MCP Gateway.</div>';
            return;
        }
        
        tokensList.innerHTML = tokens.map(token => `
            <div class="token-item">
                <div class="token-info">
                    <div class="token-description">${this.escapeHtml(token.description || 'No description')}</div>
                    <div class="token-meta">
                        Created: ${new Date(token.created_at).toLocaleDateString()}
                        ${token.expires_at ? ` | Expires: ${new Date(token.expires_at).toLocaleDateString()}` : ''}
                        ${token.last_used ? ` | Last used: ${new Date(token.last_used).toLocaleDateString()}` : ''}
                    </div>
                    <div class="token-meta">Token: ****...${token.token ? token.token.slice(-4) : '****'}</div>
                </div>
                <button class="btn btn-sm btn-danger" onclick="adminPanel.revokeToken(${token.id})">Revoke</button>
            </div>
        `).join('');
    }

    async createToken() {
        if (!this.authEnabled) return;
        
        const description = document.getElementById('tokenDescription').value;
        const expiresIn = document.getElementById('tokenExpiry').value;
        
        // Convert expiry period to actual date
        let expiresAt = null;
        if (expiresIn) {
            const now = new Date();
            switch (expiresIn) {
                case '14d':
                    expiresAt = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);
                    break;
                case '30d':
                    expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
                    break;
                case '90d':
                    expiresAt = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
                    break;
                case '1y':
                    expiresAt = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate());
                    break;
            }
        }
        
        try {
            const response = await this.makeAuthenticatedRequest('/auth/tokens', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    description,
                    expires_at: expiresAt ? expiresAt.toISOString() : null
                })
            });
            
            if (response.ok) {
                const tokenData = await response.json();
                const tokenValue = tokenData.token;
                
                // Show success message with the actual token value
                const successMessage = `
                    <strong>Token created successfully!</strong><br>
                    <div style="margin-top: 10px; padding: 10px; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; display: flex; align-items: center; gap: 10px;">
                        <div style="flex: 1; font-family: monospace; word-break: break-all;">${tokenValue}</div>
                        <button onclick="adminPanel.copyToClipboard('${tokenValue}', this)" style="padding: 4px 8px; background: #007AFF; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; white-space: nowrap;">
                            Copy
                        </button>
                    </div>
                    <div style="margin-top: 10px; color: #dc3545; font-weight: bold;">
                        ⚠️ This token will not be shown again. Please copy it now!
                    </div>
                `;
                this.showSuccess('tokenSuccess', successMessage);
                
                document.getElementById('createTokenForm').reset();
                await this.loadTokens();
            } else {
                const error = await response.text();
                this.showError('tokenError', error);
            }
        } catch (error) {
            this.showError('tokenError', 'Failed to create token: ' + error.message);
        }
    }

    async revokeToken(tokenId) {
        if (!this.authEnabled) return;
        
        if (!confirm('Are you sure you want to revoke this token?')) {
            return;
        }
        
        try {
            console.log('Revoking token ID:', tokenId);
            const response = await this.makeAuthenticatedRequest(`/auth/tokens/revoke?id=${tokenId}`, {
                method: 'DELETE'
            });
            
            console.log('Revoke response status:', response.status);
            
            if (response.ok) {
                console.log('Token revoked successfully, reloading token list...');
                this.showSuccess('tokenSuccess', 'Token revoked successfully');
                // Reload the tokens list immediately
                await this.loadTokens();
            } else {
                const errorText = await response.text();
                console.error('Revoke token error:', errorText);
                this.showError('tokenError', 'Failed to revoke token: ' + errorText);
            }
        } catch (error) {
            console.error('Revoke token exception:', error);
            this.showError('tokenError', 'Failed to revoke token: ' + error.message);
        }
    }

    // Cache management
    clearDataCache() {
        this.lastServersData = null;
        if (this.statisticsTab) {
            this.statisticsTab.clearCache();
        }
    }

    // Common methods for server management

    async loadServers() {
        try {
            // Load both server list and gateway status to get tools information
            const [serversResponse, statusResponse] = await Promise.all([
                this.makeAuthenticatedRequest('/api/upstream-servers'),
                this.makeAuthenticatedRequest('/gateway/status')
            ]);
            
            const serversResult = await serversResponse.json();
            const statusResult = await statusResponse.json();
            
            if (serversResult.success) {
                // Merge server data with tools information from gateway status
                const servers = serversResult.data.servers || [];
                const upstreamServers = statusResult.gateway?.upstream_servers || [];
                
                // Create a map of server names to their tools
                const toolsMap = {};
                upstreamServers.forEach(upstream => {
                    toolsMap[upstream.name] = {
                        tool_details: upstream.tool_details || [],
                        connected: upstream.connected
                    };
                });
                
                // Add tools information to each server
                servers.forEach(server => {
                    const toolsInfo = toolsMap[server.name] || { tool_details: [], connected: false };
                    server.tool_details = toolsInfo.tool_details;
                    server.runtime_connected = toolsInfo.connected;
                });
                
                // Only update DOM if data has changed
                const serversKey = JSON.stringify(servers.map(s => ({
                    id: s.id,
                    name: s.name,
                    status: s.status,
                    enabled: s.enabled,
                    runtime_connected: s.runtime_connected,
                    tool_details_count: s.tool_details?.length || 0
                })));
                
                if (this.lastServersData !== serversKey) {
                    this.renderServers(servers);
                    this.lastServersData = serversKey;
                }
                
                document.getElementById('serverCount').textContent = `${serversResult.data.count || 0} servers`;
                
                // Update last refresh time
                this.updateLastRefreshTime();
            } else {
                throw new Error(serversResult.error || 'Failed to load servers');
            }
        } catch (error) {
            console.error('Error loading servers:', error);
            document.getElementById('serversList').innerHTML = 
                `<div class="error">Error loading servers: ${error.message}</div>`;
        }
    }

    renderServers(servers) {
        const serversList = document.getElementById('serversList');
        
        if (servers.length === 0) {
            serversList.innerHTML = '<div class="loading">No servers configured</div>';
            return;
        }
        
        serversList.innerHTML = servers.map((server, index) => {
            const toolDetails = server.tool_details || [];
            const isRuntimeConnected = server.runtime_connected || false;
            
            // Use the database status, but show "disabled" if the server is not enabled
            const displayStatus = !server.enabled ? 'disabled' : (server.status || 'disconnected');
            
            const toolsTableContent = toolDetails.length > 0 
                ? `<table class="tools-table">
                    <thead>
                        <tr>
                            <th>Tool Name</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${toolDetails.map(tool => `
                            <tr>
                                <td class="tool-name">${this.escapeHtml(tool.name)}</td>
                                <td class="tool-description">${this.escapeHtml(tool.description || 'No description available')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>`
                : '<div class="no-tools">No tools available</div>';
            
            const displayUrl = server.type === 'stdio' && server.command && server.command.length > 0
                ? server.command.join(' ')
                : server.url || '';
            
            // Build authentication info
            let authInfo = '';
            if (server.auth_type && server.type === 'http') {
                switch (server.auth_type) {
                    case 'bearer':
                        authInfo = '<span>Auth: Bearer Token</span>';
                        break;
                    case 'basic':
                        authInfo = `<span>Auth: Basic (${this.escapeHtml(server.auth_username || 'Unknown')})</span>`;
                        break;
                    case 'api-key':
                        authInfo = `<span>Auth: API Key (${this.escapeHtml(server.auth_header_name || 'X-API-Key')})</span>`;
                        break;
                    default:
                        authInfo = `<span>Auth: ${this.escapeHtml(server.auth_type)}</span>`;
                }
            }
            
            return `
                <div class="server-item">
                    <div class="server-main">
                        <div class="server-info">
                            <div class="server-name">${this.escapeHtml(server.name)}</div>
                            <div class="server-url">${this.escapeHtml(displayUrl)}</div>
                            ${server.description ? `<div class="server-description">${this.escapeHtml(server.description)}</div>` : ''}
                            <div class="server-meta">
                                <span class="server-status status-${displayStatus}">
                                    ${displayStatus.charAt(0).toUpperCase() + displayStatus.slice(1)}
                                </span>
                                <span>Type: ${server.type}</span>
                                ${server.prefix ? `<span>Prefix: ${this.escapeHtml(server.prefix)}</span>` : ''}
                                ${authInfo}
                            </div>
                        </div>
                        <div class="server-actions">
                            <button class="btn btn-sm btn-secondary" onclick="adminPanel.editServer(${server.id})">Edit</button>
                            <button class="btn btn-sm ${server.enabled ? 'btn-secondary' : 'btn'}" 
                                    onclick="adminPanel.toggleServer(${server.id})">
                                ${server.enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button class="btn btn-sm btn-secondary" onclick="adminPanel.viewServerLogs(${server.id}, '${this.escapeHtml(server.name)}')">View Logs</button>
                            <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteServer(${server.id})">Delete</button>
                        </div>
                    </div>
                    <div class="server-tools">
                        <div class="tools-header" onclick="adminPanel.toggleToolsVisibility(${index})">
                            <span class="tools-toggle" id="tools-toggle-${index}">▶</span>
                            Available Tools
                            <span class="tools-count">${toolDetails.length}</span>
                        </div>
                        <div class="tools-content" id="tools-content-${index}">
                            ${toolsTableContent}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    toggleToolsVisibility(serverIndex) {
        const content = document.getElementById(`tools-content-${serverIndex}`);
        const toggle = document.getElementById(`tools-toggle-${serverIndex}`);
        
        if (content.classList.contains('expanded')) {
            content.classList.remove('expanded');
            toggle.textContent = '▶';
            toggle.classList.remove('expanded');
        } else {
            content.classList.add('expanded');
            toggle.textContent = '▼';
            toggle.classList.add('expanded');
        }
    }

    async editServer(id) {
        try {
            const response = await this.makeAuthenticatedRequest(`/api/upstream-servers/${id}`);
            const result = await response.json();
            
            if (result.success) {
                this.currentEditingId = id;
                const server = result.data;
                
                document.getElementById('modalTitle').textContent = 'Edit Server';
                document.getElementById('serverName').value = server.name || '';
                document.getElementById('serverUrl').value = server.url || '';
                document.getElementById('serverType').value = server.type || 'websocket';
                document.getElementById('serverTimeout').value = server.timeout || '30s';
                document.getElementById('serverPrefix').value = server.prefix || '';
                document.getElementById('serverDescription').value = server.description || '';
                document.getElementById('serverEnabled').checked = server.enabled;
                
                // Handle command field for stdio servers
                if (server.command && Array.isArray(server.command) && server.command.length > 0) {
                    document.getElementById('serverCommand').value = server.command.join(' ');
                } else {
                    document.getElementById('serverCommand').value = '';
                }
                
                // Handle authentication fields for HTTP servers
                if (server.auth_type) {
                    document.getElementById('authType').value = server.auth_type;
                    
                    switch (server.auth_type) {
                        case 'bearer':
                            document.getElementById('bearerToken').value = server.auth_token || '';
                            break;
                        case 'basic':
                            document.getElementById('basicUsername').value = server.auth_username || '';
                            document.getElementById('basicPassword').value = server.auth_password || '';
                            break;
                        case 'api-key':
                            document.getElementById('apiKey').value = server.auth_api_key || '';
                            document.getElementById('apiKeyHeader').value = server.auth_header_name || 'X-API-Key';
                            break;
                    }
                } else {
                    // Reset authentication fields
                    document.getElementById('authType').value = '';
                    document.getElementById('bearerToken').value = '';
                    document.getElementById('basicUsername').value = '';
                    document.getElementById('basicPassword').value = '';
                    document.getElementById('apiKey').value = '';
                    document.getElementById('apiKeyHeader').value = 'X-API-Key';
                }
                
                // Set correct field visibility based on type
                toggleServerFields();
                toggleAuthFields();
                
                document.getElementById('serverModal').style.display = 'block';
            } else {
                alert('Error loading server: ' + (result.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Error loading server: ' + error.message);
        }
    }

    async toggleServer(id) {
        try {
            const response = await this.makeAuthenticatedRequest(`/api/upstream-servers/${id}/toggle`, {
                method: 'POST'
            });
            const result = await response.json();
            
            if (result.success) {
                this.clearDataCache(); // Clear cache to force UI update
                await this.loadServers();
                await this.loadStats();
            } else {
                alert('Error toggling server: ' + (result.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Error toggling server: ' + error.message);
        }
    }

    async deleteServer(id) {
        if (confirm('Are you sure you want to delete this server?')) {
            try {
                const response = await this.makeAuthenticatedRequest(`/api/upstream-servers/${id}`, {
                    method: 'DELETE'
                });
                const result = await response.json();
                
                if (result.success) {
                    this.clearDataCache(); // Clear cache to force UI update
                    await this.loadServers();
                    await this.loadStats();
                } else {
                    alert('Error deleting server: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                alert('Error deleting server: ' + error.message);
            }
        }
    }

    // Utility methods
    showError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        errorElement.textContent = message;
        errorElement.classList.remove('hidden');
        setTimeout(() => errorElement.classList.add('hidden'), 5000);
    }

    showSuccess(elementId, message) {
        const successElement = document.getElementById(elementId);
        // Check if message contains HTML tags
        if (message.includes('<')) {
            successElement.innerHTML = message;
        } else {
            successElement.textContent = message;
        }
        successElement.classList.remove('hidden');
        setTimeout(() => successElement.classList.add('hidden'), 8000); // Increased timeout for token display
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    viewServerLogs(serverId, serverName) {
        // Switch to logs tab
        this.switchTab('logs');
        
        // Wait a moment for the tab to load, then select the server log
        setTimeout(() => {
            loadServerLogs().then(() => {
                // Find and click the log item for this server
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

    updateLastRefreshTime() {
        const lastUpdateElement = document.getElementById('lastUpdateTime');
        if (lastUpdateElement) {
            const now = new Date();
            const timeString = now.toLocaleTimeString();
            lastUpdateElement.textContent = `Last updated: ${timeString}`;
            lastUpdateElement.style.color = '#86868b'; // Reset to default color
        }
    }
    
    showRefreshingIndicator(show) {
        const lastUpdateElement = document.getElementById('lastUpdateTime');
        
        if (show) {
            // Only show indicator after a brief delay to avoid flashing
            this.refreshIndicatorTimeout = setTimeout(() => {
                if (lastUpdateElement) {
                    lastUpdateElement.textContent = 'Updating...';
                    lastUpdateElement.style.color = '#007AFF';
                }
            }, 200); // 200ms delay
        } else {
            // Clear the timeout if refresh finished quickly
            if (this.refreshIndicatorTimeout) {
                clearTimeout(this.refreshIndicatorTimeout);
                this.refreshIndicatorTimeout = null;
            }
            // Reset the indicator immediately when done
            if (lastUpdateElement) {
                this.updateLastRefreshTime();
            }
        }
    }

    // Utility methods
    copyToClipboard(text, buttonElement) {
        navigator.clipboard.writeText(text).then(() => {
            // Temporarily change button text to show success
            const originalText = buttonElement.textContent;
            buttonElement.textContent = 'Copied!';
            buttonElement.style.background = '#28a745';
            
            setTimeout(() => {
                buttonElement.textContent = originalText;
                buttonElement.style.background = '#007AFF';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                // Show success feedback
                const originalText = buttonElement.textContent;
                buttonElement.textContent = 'Copied!';
                buttonElement.style.background = '#28a745';
                
                setTimeout(() => {
                    buttonElement.textContent = originalText;
                    buttonElement.style.background = '#007AFF';
                }, 2000);
            } catch (err) {
                console.error('Fallback copy failed: ', err);
                alert('Failed to copy to clipboard. Please copy manually.');
            }
            document.body.removeChild(textArea);
        });
    }
}

// Global functions for onclick handlers
let adminPanel;

document.addEventListener('DOMContentLoaded', function() {
    adminPanel = new AdminPanel();
    
    // Clean up auto-refresh timer when page is unloaded
    window.addEventListener('beforeunload', function() {
        if (adminPanel) {
            adminPanel.stopAutoRefresh();
        }
    });
    
    // Pause auto-refresh when page is not visible (optional optimization)
    document.addEventListener('visibilitychange', function() {
        if (adminPanel) {
            if (document.hidden) {
                adminPanel.autoRefreshEnabled = false;
            } else {
                adminPanel.autoRefreshEnabled = true;
            }
        }
    });
});

function showAddServerModal() {
    adminPanel.currentEditingId = null;
    document.getElementById('modalTitle').textContent = 'Add Server';
    document.getElementById('serverForm').reset();
    document.getElementById('serverEnabled').checked = true;
    
    // Reset authentication fields
    document.getElementById('authType').value = '';
    document.getElementById('bearerToken').value = '';
    document.getElementById('basicUsername').value = '';
    document.getElementById('basicPassword').value = '';
    document.getElementById('apiKey').value = '';
    document.getElementById('apiKeyHeader').value = 'X-API-Key';
    
    toggleServerFields();
    toggleAuthFields();
    document.getElementById('serverModal').style.display = 'block';
}

function toggleServerFields() {
    const serverType = document.getElementById('serverType').value;
    const urlGroup = document.getElementById('urlGroup');
    const commandGroup = document.getElementById('commandGroup');
    const authSection = document.getElementById('authSection');
    const serverUrl = document.getElementById('serverUrl');
    const serverCommand = document.getElementById('serverCommand');
    
    if (serverType === 'stdio') {
        urlGroup.classList.add('hidden');
        commandGroup.classList.remove('hidden');
        authSection.classList.remove('visible');
        serverUrl.required = false;
        serverCommand.required = true;
    } else {
        urlGroup.classList.remove('hidden');
        commandGroup.classList.add('hidden');
        serverUrl.required = true;
        serverCommand.required = false;
        
        // Show auth section for HTTP servers
        if (serverType === 'http') {
            authSection.classList.add('visible');
        } else {
            authSection.classList.remove('visible');
        }
    }
}

function toggleAuthFields() {
    const authType = document.getElementById('authType').value;
    const bearerFields = document.getElementById('bearerFields');
    const basicFields = document.getElementById('basicFields');
    const apiKeyFields = document.getElementById('apiKeyFields');
    
    // Hide all auth fields
    bearerFields.classList.remove('active');
    basicFields.classList.remove('active');
    apiKeyFields.classList.remove('active');
    
    // Show relevant auth fields
    switch (authType) {
        case 'bearer':
            bearerFields.classList.add('active');
            break;
        case 'basic':
            basicFields.classList.add('active');
            break;
        case 'api-key':
            apiKeyFields.classList.add('active');
            break;
    }
}

function closeModal() {
    document.getElementById('serverModal').style.display = 'none';
}

async function refreshConnections() {
    try {
        // Temporarily pause auto-refresh during manual refresh
        const wasAutoRefreshEnabled = adminPanel.autoRefreshEnabled;
        adminPanel.autoRefreshEnabled = false;
        adminPanel.showRefreshingIndicator(true);
        
        const response = await adminPanel.makeAuthenticatedRequest('/gateway/refresh', {
            method: 'POST'
        });
        const result = await response.json();
        
        if (result.success) {
            adminPanel.clearDataCache(); // Clear cache to force UI update
            await adminPanel.loadServers();
            await adminPanel.loadStats();
            alert('Connections refreshed successfully');
        } else {
            alert('Error refreshing connections: ' + (result.error || 'Unknown error'));
        }
        
        // Re-enable auto-refresh
        adminPanel.autoRefreshEnabled = wasAutoRefreshEnabled;
    } catch (error) {
        // Re-enable auto-refresh on error too
        adminPanel.autoRefreshEnabled = wasAutoRefreshEnabled || true;
        alert('Error refreshing connections: ' + error.message);
    }
}

async function loadServers() {
    // Temporarily pause auto-refresh during manual refresh
    const wasAutoRefreshEnabled = adminPanel.autoRefreshEnabled;
    adminPanel.autoRefreshEnabled = false;
    adminPanel.showRefreshingIndicator(true);
    
    try {
        adminPanel.clearDataCache(); // Clear cache to force UI update
        await adminPanel.loadServers();
        await adminPanel.loadStats();
    } finally {
        // Re-enable auto-refresh
        adminPanel.autoRefreshEnabled = wasAutoRefreshEnabled;
    }
}

// Server form submission
document.addEventListener('DOMContentLoaded', function() {
    // Make toggleAuthFields available globally
    window.toggleAuthFields = toggleAuthFields;
    
    document.getElementById('serverForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const serverType = document.getElementById('serverType').value;
        const serverData = {
            name: document.getElementById('serverName').value,
            type: serverType,
            timeout: document.getElementById('serverTimeout').value,
            prefix: document.getElementById('serverPrefix').value,
            description: document.getElementById('serverDescription').value,
            enabled: document.getElementById('serverEnabled').checked
        };

        // Add URL or Command based on type
        if (serverType === 'stdio') {
            const commandString = document.getElementById('serverCommand').value.trim();
            if (commandString) {
                // Split command string into array, handling quoted arguments
                serverData.command = commandString.match(/(?:[^\s"]+|"[^"]*")+/g)?.map(arg => 
                    arg.startsWith('"') && arg.endsWith('"') ? arg.slice(1, -1) : arg
                ) || [];
            } else {
                serverData.command = [];
            }
            serverData.url = ''; // Empty URL for stdio
        } else {
            serverData.url = document.getElementById('serverUrl').value;
            // Don't send command field for non-stdio types to avoid confusion
        }

        // Add authentication data for HTTP servers
        if (serverType === 'http') {
            const authType = document.getElementById('authType').value;
            if (authType) {
                serverData.auth = {
                    type: authType
                };
                
                switch (authType) {
                    case 'bearer':
                        serverData.auth.bearer_token = document.getElementById('bearerToken').value;
                        break;
                    case 'basic':
                        serverData.auth.username = document.getElementById('basicUsername').value;
                        serverData.auth.password = document.getElementById('basicPassword').value;
                        break;
                    case 'api-key':
                        serverData.auth.api_key = document.getElementById('apiKey').value;
                        serverData.auth.header_name = document.getElementById('apiKeyHeader').value || 'X-API-Key';
                        break;
                }
            }
        }
        
        try {
            const url = adminPanel.currentEditingId 
                ? `/api/upstream-servers/${adminPanel.currentEditingId}`
                : '/api/upstream-servers';
            const method = adminPanel.currentEditingId ? 'PUT' : 'POST';
            
            const response = await adminPanel.makeAuthenticatedRequest(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(serverData)
            });
            
            const result = await response.json();
            
            if (result.success) {
                closeModal();
                adminPanel.clearDataCache(); // Clear cache to force UI update
                await adminPanel.loadServers();
                await adminPanel.loadStats();
            } else {
                alert('Error saving server: ' + (result.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Error saving server: ' + error.message);
        }
    });
});

// Logs functionality
let currentLogServerId = null;
let currentLogFilename = null;
let logsAutoRefreshEnabled = false;
let logsAutoRefreshTimer = null;

async function loadServerLogs() {
    try {
        const response = await adminPanel.makeAuthenticatedRequest('/api/logs');
        const result = await response.json();
        
        if (result.success) {
            displayLogsList(result.data.logs);
        } else {
            throw new Error(result.error || 'Failed to load logs');
        }
    } catch (error) {
        console.error('Error loading logs:', error);
        document.getElementById('logsListContainer').innerHTML = 
            '<div class="error">Error loading logs: ' + error.message + '</div>';
    }
}

function displayLogsList(logs) {
    const container = document.getElementById('logsListContainer');
    
    if (logs.length === 0) {
        container.innerHTML = '<div class="no-logs">No log files found</div>';
        return;
    }
    
    const logsHTML = logs.map(log => `
        <div class="log-item" onclick="selectLog(${log.server_id}, '${log.server_name}', '${log.filename}')">
            <div class="log-item-name">${log.server_name}</div>
            <div class="log-item-info">
                ID: ${log.server_id} | Size: ${formatFileSize(log.size)} | 
                Modified: ${new Date(log.modified).toLocaleString()}
            </div>
        </div>
    `).join('');
    
    container.innerHTML = logsHTML;
}

async function loadLog(filename) {
    // Update active state
    document.querySelectorAll('.log-item').forEach(item => item.classList.remove('active'));
    event.target.closest('.log-item').classList.add('active');
    
    currentLogServerId = null; // Clear server ID for generic logs
    currentLogFilename = filename;
    
    // Update log viewer header
    document.getElementById('logViewerTitle').textContent = `Gateway Log: ${filename}`;
    document.getElementById('refreshLogBtn').disabled = false;
    document.getElementById('downloadLogBtn').disabled = false;
    
    // Load log content
    await loadGenericLogContent(filename);
}

async function selectLog(serverId, serverName, filename) {
    // Update active state
    document.querySelectorAll('.log-item').forEach(item => item.classList.remove('active'));
    event.target.closest('.log-item').classList.add('active');
    
    currentLogServerId = serverId;
    
    // Update log viewer header
    document.getElementById('logViewerTitle').textContent = `Logs for ${serverName}`;
    document.getElementById('refreshLogBtn').disabled = false;
    document.getElementById('downloadLogBtn').disabled = false;
    
    // Load log content
    await loadLogContent(serverId);
}

async function loadLogContent(serverId) {
    const logContent = document.getElementById('logContent');
    const tailCheckbox = document.getElementById('tailLogsCheckbox');
    
    try {
        let url = `/api/upstream-servers/${serverId}/logs`;
        if (tailCheckbox.checked) {
            url += '?tail=true&lines=100';
        }
        
        const response = await adminPanel.makeAuthenticatedRequest(url);
        const result = await response.json();
        
        if (result.success) {
            if (result.data.content.trim() === '') {
                logContent.innerHTML = '<div class="no-log-selected">Log file is empty</div>';
            } else {
                const lines = result.data.content.split('\n').map(line => 
                    `<div class="log-line">${escapeHtml(line)}</div>`
                ).join('');
                logContent.innerHTML = lines;
                
                // Auto-scroll to bottom
                logContent.scrollTop = logContent.scrollHeight;
            }
            updateLogsLastRefreshTime();
        } else {
            logContent.innerHTML = `<div class="error">Error loading log: ${result.error}</div>`;
        }
    } catch (error) {
        console.error('Error loading log content:', error);
        logContent.innerHTML = `<div class="error">Error loading log: ${error.message}</div>`;
    }
}

async function loadGenericLogContent(filename) {
    const logContent = document.getElementById('logContent');
    const tailCheckbox = document.getElementById('tailLogsCheckbox');
    
    try {
        let url = `/api/logs/${filename}`;
        if (tailCheckbox.checked) {
            url += '?tail=true&lines=100';
        }
        
        const response = await adminPanel.makeAuthenticatedRequest(url);
        const result = await response.json();
        
        if (result.success) {
            if (result.data.content.trim() === '') {
                logContent.innerHTML = '<div class="no-log-content">This log file is empty</div>';
            } else {
                const lines = result.data.content.split('\n').map(line => 
                    `<div class="log-line">${escapeHtml(line)}</div>`
                ).join('');
                logContent.innerHTML = lines;
                
                // Auto-scroll to bottom
                logContent.scrollTop = logContent.scrollHeight;
            }
            updateLogsLastRefreshTime();
        } else {
            logContent.innerHTML = `<div class="error">Error loading log: ${result.error}</div>`;
        }
    } catch (error) {
        console.error('Error loading log content:', error);
        logContent.innerHTML = `<div class="error">Error loading log: ${error.message}</div>`;
    }
}

function refreshCurrentLog() {
    if (currentLogServerId) {
        loadLogContent(currentLogServerId);
    } else if (currentLogFilename) {
        loadGenericLogContent(currentLogFilename);
    }
}

async function downloadCurrentLog() {
    if (currentLogServerId) {
        try {
            const url = `/api/upstream-servers/${currentLogServerId}/logs?download=true`;
            const response = await adminPanel.makeAuthenticatedRequest(url);
            
            if (response.ok) {
                const blob = await response.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = `server-${currentLogServerId}.log`;
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
    } else if (currentLogFilename) {
        try {
            const url = `/api/logs/${currentLogFilename}?download=true`;
            const response = await adminPanel.makeAuthenticatedRequest(url);
            
            if (response.ok) {
                const blob = await response.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = currentLogFilename;
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

function toggleLogTail() {
    if (currentLogServerId) {
        loadLogContent(currentLogServerId);
    } else if (currentLogFilename) {
        loadGenericLogContent(currentLogFilename);
    }
}

function toggleLogsAutoRefresh() {
    const toggle = document.getElementById('logsAutoRefreshToggle');
    logsAutoRefreshEnabled = !logsAutoRefreshEnabled;
    
    if (logsAutoRefreshEnabled) {
        toggle.classList.add('active');
        startLogsAutoRefresh();
    } else {
        toggle.classList.remove('active');
        stopLogsAutoRefresh();
    }
}

function startLogsAutoRefresh() {
    if (logsAutoRefreshTimer) {
        clearInterval(logsAutoRefreshTimer);
    }
    
    logsAutoRefreshTimer = setInterval(() => {
        if (currentLogServerId && document.getElementById('logsTab').style.display !== 'none') {
            loadLogContent(currentLogServerId);
        }
    }, 5000); // Refresh every 5 seconds
}

function stopLogsAutoRefresh() {
    if (logsAutoRefreshTimer) {
        clearInterval(logsAutoRefreshTimer);
        logsAutoRefreshTimer = null;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateLogsLastRefreshTime() {
    const lastUpdateElement = document.getElementById('logsLastUpdateTime');
    if (lastUpdateElement) {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        lastUpdateElement.textContent = `Last updated: ${timeString}`;
        lastUpdateElement.style.color = '#86868b';
    }
}
