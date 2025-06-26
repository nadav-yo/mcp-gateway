// MCP Gateway Admin Panel JavaScript

class AdminPanel {
    constructor() {
        // Check if auth is enabled (injected by server)
        this.authEnabled = window.AUTH_ENABLED || false;
        this.token = null;
        this.user = null;
        this.currentEditingId = null;
        
        if (this.authEnabled) {
            this.token = localStorage.getItem('mcp_token');
        }
        
        this.init();
    }

    async init() {
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
                this.loadStatsForTab();
                break;
        }
    }

    async loadInitialData() {
        await this.loadStats();
        await this.loadServers();
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
            const cacheBuster = new Date().getTime();
            const response = await this.makeAuthenticatedRequest(`/auth/tokens?_=${cacheBuster}`);
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

    // Common methods for server management
    async loadStats() {
        try {
            const response = await this.makeAuthenticatedRequest('/gateway/stats');
            const stats = await response.json();
            
            // Update server management tab stats
            document.getElementById('totalServers').textContent = stats.upstream_servers || 0;
            document.getElementById('connectedServers').textContent = stats.connected_servers || 0;
            document.getElementById('totalTools').textContent = stats.total_tools || 0;
            document.getElementById('totalResources').textContent = stats.total_resources || 0;
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }
    
    async loadStatsForTab() {
        try {
            const [statsResponse, infoResponse] = await Promise.all([
                this.makeAuthenticatedRequest('/gateway/stats'),
                this.makeAuthenticatedRequest('/info')
            ]);
            
            const stats = await statsResponse.json();
            const info = await infoResponse.json();
            
            // Update statistics tab stats
            document.getElementById('totalServersStats').textContent = stats.upstream_servers || 0;
            document.getElementById('connectedServersStats').textContent = stats.connected_servers || 0;
            document.getElementById('totalToolsStats').textContent = stats.total_tools || 0;
            document.getElementById('totalResourcesStats').textContent = stats.total_resources || 0;
            document.getElementById('requestsProcessedStats').textContent = stats.requests_processed || 0;
            
            // Update gateway information
            document.getElementById('gatewayName').textContent = info.name || 'MCP Gateway';
            document.getElementById('gatewayVersion').textContent = info.version || '1.0.0';
            document.getElementById('lastUpdated').textContent = new Date().toLocaleString();
            
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
                
                this.renderServers(servers);
                document.getElementById('serverCount').textContent = `${serversResult.data.count || 0} servers`;
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
            const displayStatus = isRuntimeConnected && server.enabled ? 'connected' : 
                                server.enabled ? 'disconnected' : 'disabled';
            
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
            
            return `
                <div class="server-item">
                    <div class="server-main">
                        <div class="server-info">
                            <div class="server-name">${this.escapeHtml(server.name)}</div>
                            <div class="server-url">${this.escapeHtml(server.url)}</div>
                            <div class="server-meta">
                                <span class="server-status status-${displayStatus}">
                                    ${displayStatus.charAt(0).toUpperCase() + displayStatus.slice(1)}
                                </span>
                                <span>Type: ${server.type}</span>
                                ${server.prefix ? `<span>Prefix: ${this.escapeHtml(server.prefix)}</span>` : ''}
                                <span>Enabled: ${server.enabled ? 'Yes' : 'No'}</span>
                            </div>
                        </div>
                        <div class="server-actions">
                            <button class="btn btn-sm btn-secondary" onclick="adminPanel.editServer(${server.id})">Edit</button>
                            <button class="btn btn-sm ${server.enabled ? 'btn-secondary' : 'btn'}" 
                                    onclick="adminPanel.toggleServer(${server.id})">
                                ${server.enabled ? 'Disable' : 'Enable'}
                            </button>
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
});

function showAddServerModal() {
    adminPanel.currentEditingId = null;
    document.getElementById('modalTitle').textContent = 'Add Server';
    document.getElementById('serverForm').reset();
    document.getElementById('serverEnabled').checked = true;
    document.getElementById('serverModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('serverModal').style.display = 'none';
}

async function refreshConnections() {
    try {
        const response = await adminPanel.makeAuthenticatedRequest('/gateway/refresh', {
            method: 'POST'
        });
        const result = await response.json();
        
        if (result.success) {
            await adminPanel.loadServers();
            await adminPanel.loadStats();
            alert('Connections refreshed successfully');
        } else {
            alert('Error refreshing connections: ' + (result.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Error refreshing connections: ' + error.message);
    }
}

async function loadServers() {
    await adminPanel.loadServers();
}

// Server form submission
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('serverForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const serverData = {
            name: document.getElementById('serverName').value,
            url: document.getElementById('serverUrl').value,
            type: document.getElementById('serverType').value,
            timeout: document.getElementById('serverTimeout').value,
            prefix: document.getElementById('serverPrefix').value,
            description: document.getElementById('serverDescription').value,
            enabled: document.getElementById('serverEnabled').checked
        };
        
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
