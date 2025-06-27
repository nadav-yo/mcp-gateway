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
        
        // Initialize user info component
        this.userInfoManager = new UserInfoManager();
        
        // Initialize statistics tab
        this.statisticsTab = new StatisticsTab(this);
        
        // Initialize logs tab
        this.logsTab = new LogsTab(this);
        
        // Initialize user management (only for auth mode)
        if (this.authEnabled) {
            this.userManager = new UserManager(this);
            // Make userManager globally accessible for onclick handlers
            window.userManager = this.userManager;
            
            // Initialize token management
            this.tokenManager = new TokenManager(this);
            // Make tokenManager globally accessible for onclick handlers
            window.tokenManager = this.tokenManager;
        }
        
        this.init();
    }

    async loadUserInfoHTML() {
        try {
            const response = await fetch('/static/userinfo.html');
            const html = await response.text();
            document.getElementById('userInfoPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading userinfo HTML:', error);
        }
    }

    async init() {
        // Load modular HTML components
        await Promise.all([
            this.loadUserInfoHTML(),
            this.loadStatisticsHTML(),
            this.loadLogsHTML(),
            ...(this.authEnabled ? [this.loadUsersHTML(), this.loadTokensHTML()] : [])
        ]);
        
        this.setupEventListeners();
        
        if (this.authEnabled) {
            this.setupAuthUI();
            // Since we're on the admin page, we're already authenticated
            // Get token from localStorage or try to validate
            if (this.token) {
                await this.userInfoManager.initialize();
                this.showAdminPanel(true);
                await this.tokenManager.loadTokens();
                await this.loadInitialData();
                this.startAutoRefresh();
            } else {
                // No token in localStorage, redirect to login
                window.location.href = '/ui/login';
            }
        } else {
            // No auth required
            this.showAdminPanel(false);
            await this.userInfoManager.initialize();
            await this.loadInitialData();
            this.startAutoRefresh();
        }
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

    async loadLogsHTML() {
        try {
            const response = await fetch('/static/logs.html');
            const html = await response.text();
            document.getElementById('logsTabPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading logs HTML:', error);
        }
    }

    async loadUsersHTML() {
        try {
            const response = await fetch('/static/users.html');
            const html = await response.text();
            document.getElementById('usersTabPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading users HTML:', error);
        }
    }

    async loadTokensHTML() {
        try {
            const response = await fetch('/static/tokens.html');
            const html = await response.text();
            document.getElementById('tokensTabPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading tokens HTML:', error);
        }
    }
    
    setupAuthUI() {
        // Hide description for auth mode
        document.getElementById('adminDescription').style.display = 'none';
    }

    async checkAuth() {
        try {
            const response = await this.makeAuthenticatedRequest('/auth/tokens');
            if (response.ok) {
                this.showAdminPanel(true);
                if (this.authEnabled && this.tokenManager) {
                    await this.tokenManager.loadTokens();
                }
                await this.loadInitialData();
                this.startAutoRefresh();
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
                if (this.tokenManager) {
                    await this.tokenManager.loadTokens();
                }
                await this.loadInitialData();
                this.startAutoRefresh();
            } else {
                const error = await response.text();
                this.showError('loginError', error);
            }
        } catch (error) {
            this.showError('loginError', 'Login failed: ' + error.message);
        }
    }

    async logout() {
        this.stopAutoRefresh();
        
        // Call server-side logout to revoke token
        if (this.token) {
            try {
                await fetch('/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.log('Logout API call failed:', error);
                // Continue with client-side logout even if server call fails
            }
        }
        
        // Clear client-side state
        this.token = null;
        this.user = null;
        localStorage.removeItem('mcp_token');
        
        // Clear cookie
        document.cookie = 'mcp_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=strict';
        
        // Redirect to login page
        window.location.href = '/ui/login';
    }

    showLogin() {
        const loginContainer = document.getElementById('loginContainer');
        const adminPanel = document.getElementById('adminPanel');
        
        if (loginContainer) {
            loginContainer.classList.remove('hidden');
        }
        if (adminPanel) {
            adminPanel.classList.add('hidden');
        }
    }

    showAdminPanel(isAuthenticated) {
        const loginContainer = document.getElementById('loginContainer');
        const adminPanel = document.getElementById('adminPanel');
        
        if (loginContainer) {
            loginContainer.classList.add('hidden');
        }
        if (adminPanel) {
            adminPanel.classList.remove('hidden');
        }
        
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
        // Tab switching (for both auth and non-auth modes)
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', async (e) => {
                await this.switchTab(e.target.dataset.tab);
            });
        });

        // Login form - use event delegation since it's loaded dynamically
        document.addEventListener('submit', (e) => {
            if (e.target.id === 'loginForm') {
                e.preventDefault();
                this.login();
            }
            if (e.target.id === 'createTokenForm') {
                e.preventDefault();
                if (this.tokenManager) {
                    this.tokenManager.createToken();
                }
            }
        });
    }

    async switchTab(tabName) {
        // Update active tab - be specific about which tab container is visible
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Find the active tab button in the visible tab container
        const authTabs = document.getElementById('authTabs');
        const noAuthTabs = document.getElementById('noAuthTabs');
        const visibleTabContainer = authTabs && !authTabs.classList.contains('hidden') ? authTabs : noAuthTabs;
        
        if (visibleTabContainer) {
            const activeTabButton = visibleTabContainer.querySelector(`[data-tab="${tabName}"]`);
            if (activeTabButton) {
                activeTabButton.classList.add('active');
            }
        }
        
        // Show/hide content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.add('hidden');
        });
        
        // Stop logs auto-refresh when leaving logs tab
        if (tabName !== 'logs' && this.logsTab) {
            this.logsTab.stopLogsAutoRefresh();
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
                await this.ensureStatsTabLoaded();
                const statsTab = document.getElementById('statsTab');
                if (statsTab) {
                    statsTab.classList.remove('hidden');
                    // Load stats when switching to stats tab
                    this.statisticsTab.loadStatsForTab();
                }
                break;
            case 'logs':
                await this.ensureLogsTabLoaded();
                const logsTab = document.getElementById('logsTab');
                if (logsTab) {
                    logsTab.classList.remove('hidden');
                    // Load logs when switching to logs tab
                    this.logsTab.loadServerLogs();
                }
                break;
            case 'users':
                await this.ensureUsersTabLoaded();
                const usersTab = document.getElementById('usersTab');
                if (usersTab) {
                    usersTab.classList.remove('hidden');
                    // Initialize and load users when switching to users tab
                    if (this.userManager) {
                        await this.userManager.init();
                    }
                }
                break;
        }
    }

    async ensureStatsTabLoaded() {
        if (!document.getElementById('statsTab')) {
            await this.loadStatisticsHTML();
        }
    }

    async ensureLogsTabLoaded() {
        if (!document.getElementById('logsTab')) {
            await this.loadLogsHTML();
        }
    }

    async ensureUsersTabLoaded() {
        if (!document.getElementById('usersTab')) {
            await this.loadUsersHTML();
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

    async viewServerLogs(serverId, serverName) {
        // Delegate to logs tab
        await this.logsTab.viewServerLogs(serverId, serverName);
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
let userManager;
let tokenManager;

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

