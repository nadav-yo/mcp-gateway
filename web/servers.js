// Servers Tab JavaScript Module

const AUTH_TYPES = {
    bearer: { fields: 'bearerFields', display: 'Bearer Token' },
    basic: { fields: 'basicFields', display: 'Basic Auth' },
    'api-key': { fields: 'apiKeyFields', display: 'API Key' }
};

class ServersTab {
    constructor(adminPanel) {
        this.adminPanel = adminPanel;
        this.lastServersData = null;
        this.currentEditingId = null;
        this.isRefreshing = false;
        this.allServers = []; // Store all servers for search filtering
        this.filteredServers = []; // Store filtered servers
        this.searchTerm = '';
        this.connectedOnlyMode = false; // Track connected-only filter state
        this.expandedStates = new Map(); // Track expanded capability sections
    }

    async initialize() {
        this.setupEventListeners();
        this.setupGlobalFunctions();
    }

    setupEventListeners() {
        const serverForm = document.getElementById('serverForm');
        if (serverForm) {
            serverForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleFormSubmit();
            });
        }
    }

    setupGlobalFunctions() {
        Object.assign(window, {
            showAddServerModal: () => this.showAddModal(),
            toggleServerFields: () => this.toggleServerFields(),
            toggleAuthFields: () => this.toggleAuthFields(),
            closeModal: () => this.closeModal(),
            refreshConnections: () => this.refreshConnections(),
            loadServers: () => this.loadServers()
        });
    }

    // UI Actions
    showAddModal() {
        this.currentEditingId = null;
        this.showModal('Add Server');
        this.resetForm();
        this.clearFormError();
    }

    async editServer(id) {
        try {
            const server = await this.fetchServer(id);
            this.currentEditingId = id;
            this.showModal('Edit Server');
            this.populateForm(server);
            this.clearFormError();
        } catch (error) {
            alert('Error loading server: ' + error.message);
        }
    }

    async toggleServer(id) {
        try {
            await this.makeRequest(`/api/upstream-servers/${id}/toggle`, 'POST');
            await this.refreshData();
        } catch (error) {
            alert('Error toggling server: ' + error.message);
        }
    }

    async deleteServer(id) {
        if (!confirm('Are you sure you want to delete this server?')) return;
        try {
            await this.makeRequest(`/api/upstream-servers/${id}`, 'DELETE');
            await this.refreshData();
        } catch (error) {
            alert('Error deleting server: ' + error.message);
        }
    }

    async viewServerLogs(serverId, serverName) {
        await this.adminPanel.logsTab.viewServerLogs(serverId, serverName);
    }

    // Data Management
    async refreshData() {
        this.adminPanel.clearDataCache();
        await Promise.all([this.loadServers(), this.adminPanel.statisticsTab.loadStats()]);
    }

    async refreshConnections() {
        // Don't manage refresh indicator here since refreshData/loadServers will handle it
        const wasAutoRefreshEnabled = this.adminPanel.autoRefreshEnabled;
        this.adminPanel.autoRefreshEnabled = false;
        
        try {
            await this.makeRequest('/gateway/refresh', 'POST');
            await this.refreshData();
            alert('Connections refreshed successfully');
        } catch (error) {
            alert('Error refreshing connections: ' + error.message);
        } finally {
            this.adminPanel.autoRefreshEnabled = wasAutoRefreshEnabled;
        }
    }

    async loadServers(skipIndicator = false) {
        // Prevent overlapping refresh operations
        if (this.isRefreshing) {
            return;
        }
        
        this.isRefreshing = true;
        const wasAutoRefreshEnabled = this.adminPanel.autoRefreshEnabled;
        this.adminPanel.autoRefreshEnabled = false;
        
        if (!skipIndicator) {
            this.adminPanel.showRefreshingIndicator(true);
        }
        
        try {
            const [serversResponse, statusResponse] = await Promise.all([
                this.adminPanel.makeAuthenticatedRequest('/api/upstream-servers'),
                this.adminPanel.makeAuthenticatedRequest('/gateway/status')
            ]);
            
            const serversResult = await serversResponse.json();
            const statusResult = await statusResponse.json();
            
            if (!serversResult.success) {
                throw new Error(serversResult.message || serversResult.error || 'Failed to load servers');
            }
            
            const servers = this.mergeServersWithTools(serversResult.data, statusResult);
            
            // Store all servers and apply current filters
            this.allServers = servers;
            this.applyFilters();
            
            if (this.shouldUpdateDOM(servers)) {
                this.adminPanel.updateLastRefreshTime();
            }
        } catch (error) {
            this.showError('Error loading servers: ' + error.message);
        } finally {
            if (!skipIndicator) {
                this.adminPanel.showRefreshingIndicator(false);
            }
            this.adminPanel.autoRefreshEnabled = wasAutoRefreshEnabled;
            this.isRefreshing = false;
        }
    }    // Search functionality
    filterServers() {
        const searchInput = document.getElementById('serverSearch');
        const clearBtn = document.getElementById('clearSearchBtn');
        
        if (!searchInput) return;
        
        this.searchTerm = searchInput.value.toLowerCase().trim();
        
        // Show/hide clear button
        if (this.searchTerm) {
            clearBtn.style.display = 'block';
        } else {
            clearBtn.style.display = 'none';
        }
        
        // Apply all filters
        this.applyFilters();
    }

    clearSearch() {
        const searchInput = document.getElementById('serverSearch');
        const clearBtn = document.getElementById('clearSearchBtn');
        
        if (searchInput) {
            searchInput.value = '';
        }
        
        this.searchTerm = '';
        clearBtn.style.display = 'none';
        
        // Apply all filters
        this.applyFilters();
    }

    // Helper Methods
    mergeServersWithTools(serversData, statusData) {
        const servers = serversData.servers || [];
        const upstreamServers = statusData.gateway?.upstream_servers || [];
        
        const toolsMap = {};
        const promptsMap = {};
        const resourcesMap = {};
        upstreamServers.forEach(upstream => {
            toolsMap[upstream.name] = {
                tool_details: upstream.tool_details || [],
                connected: upstream.connected
            };
            promptsMap[upstream.name] = {
                prompt_details: upstream.prompt_details || [],
                connected: upstream.connected
            };
            resourcesMap[upstream.name] = {
                resource_details: upstream.resource_details || [],
                connected: upstream.connected
            };
        });
        
        return servers.map(server => ({
            ...server,
            tool_details: toolsMap[server.name]?.tool_details || [],
            prompt_details: promptsMap[server.name]?.prompt_details || [],
            resource_details: resourcesMap[server.name]?.resource_details || [],
            runtime_connected: toolsMap[server.name]?.connected || false
        }));
    }

    shouldUpdateDOM(servers) {
        const serversKey = JSON.stringify(servers.map(s => ({
            id: s.id, name: s.name, status: s.status, enabled: s.enabled,
            runtime_connected: s.runtime_connected, 
            tool_details_count: s.tool_details?.length || 0,
            prompt_details_count: s.prompt_details?.length || 0,
            resource_details_count: s.resource_details?.length || 0
        })));
        
        if (this.lastServersData !== serversKey) {
            this.lastServersData = serversKey;
            return true;
        }
        return false;
    }

    updateServerCount(count) {
        document.getElementById('serverCount').textContent = `${count} servers`;
    }

    showError(message) {
        console.error(message);
        // Check if it's a general error or tool toggle error
        const errorElement = document.getElementById('serversError');
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.classList.remove('hidden');
            // Hide success message
            const successElement = document.getElementById('serversSuccess');
            if (successElement) successElement.classList.add('hidden');
            // Auto-hide after 5 seconds
            setTimeout(() => errorElement.classList.add('hidden'), 5000);
        } else {
            // Fallback to showing in servers list
            document.getElementById('serversList').innerHTML = `<div class="error">${message}</div>`;
        }
    }

    showSuccessMessage(message) {
        const successElement = document.getElementById('serversSuccess');
        if (successElement) {
            successElement.textContent = message;
            successElement.classList.remove('hidden');
            // Hide error message
            const errorElement = document.getElementById('serversError');
            if (errorElement) errorElement.classList.add('hidden');
            // Auto-hide after 3 seconds
            setTimeout(() => successElement.classList.add('hidden'), 3000);
        }
    }

    async fetchServer(id) {
        const response = await this.adminPanel.makeAuthenticatedRequest(`/api/upstream-servers/${id}`);
        const result = await response.json();
        if (!result.success) throw new Error(result.message || result.error || 'Unknown error');
        return result.data;
    }

    async makeRequest(url, method, data = null) {
        const options = { method };
        if (data) {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(data);
        }
        
        const response = await this.adminPanel.makeAuthenticatedRequest(url, options);
        const result = await response.json();
        if (!result.success) throw new Error(result.message || result.error || 'Unknown error');
        return result;
    }

    // Rendering
    renderServers(servers) {
        const serversList = document.getElementById('serversList');
        
        if (servers.length === 0) {
            // Check if we're showing filtered results or all results
            if (this.searchTerm && this.allServers.length > 0) {
                serversList.innerHTML = `<div class="loading">No servers found matching "${this.searchTerm}"</div>`;
            } else {
                serversList.innerHTML = '<div class="loading">No servers configured</div>';
            }
            return;
        }
        
        serversList.innerHTML = servers.map((server, index) => this.renderServer(server, index)).join('');
    }

    renderServer(server, index) {
        const displayStatus = !server.enabled ? 'disabled' : (server.status || 'disconnected');
        const displayUrl = server.type === 'stdio' && server.command?.length > 0
            ? server.command.join(' ') : server.url || '';
        const authInfo = this.getAuthInfo(server);
        
        // Check expanded states for this server
        const toolsExpanded = this.expandedStates.get(`${server.id}-tools`) || false;
        const promptsExpanded = this.expandedStates.get(`${server.id}-prompts`) || false;
        const resourcesExpanded = this.expandedStates.get(`${server.id}-resources`) || false;
        
        return `
            <div class="server-item">
                <div class="server-main">
                    <div class="server-info">
                        <div class="server-name-line">
                            <span class="server-name">${this.adminPanel.escapeHtml(server.name)}</span>
                            <div class="server-tags">
                                <span class="server-status status-${displayStatus}">
                                    ${displayStatus.charAt(0).toUpperCase() + displayStatus.slice(1)}
                                </span>
                                <span class="server-type-tag">Type: ${server.type}</span>
                                ${server.prefix ? `<span class="server-prefix-tag">Prefix: ${this.adminPanel.escapeHtml(server.prefix)}</span>` : ''}
                                ${authInfo}
                            </div>
                        </div>
                        <div class="server-url">${this.adminPanel.escapeHtml(displayUrl)}</div>
                        ${server.description ? `<div class="server-description">${this.adminPanel.escapeHtml(server.description)}</div>` : ''}
                    </div>
                    <div class="server-actions">
                        <button class="btn btn-sm btn-secondary" onclick="serversTab.editServer(${server.id})">Edit</button>
                        <button class="btn btn-sm ${server.enabled ? 'btn-secondary' : 'btn'}" 
                                onclick="serversTab.toggleServer(${server.id})">
                            ${server.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="serversTab.viewServerLogs(${server.id}, '${this.adminPanel.escapeHtml(server.name)}')">View Logs</button>
                        <button class="btn btn-sm btn-danger" onclick="serversTab.deleteServer(${server.id})">Delete</button>
                    </div>
                </div>
                <div class="server-capabilities">
                    <div class="capability-section">
                        <div class="capability-header" onclick="serversTab.toggleCapabilityVisibility(${server.id}, ${index}, 'tools')">
                            <span class="capability-toggle ${toolsExpanded ? 'expanded' : ''}" id="tools-toggle-${index}">${toolsExpanded ? '▼' : '▶'}</span>
                            Available Tools
                            <span class="capability-count">${server.tool_details?.length || 0}</span>
                        </div>
                        <div class="capability-content ${toolsExpanded ? 'expanded' : ''}" id="tools-content-${index}">
                            ${this.renderTools(server.tool_details || [], server.id, 'servers')}
                        </div>
                    </div>
                    
                    <div class="capability-section">
                        <div class="capability-header" onclick="serversTab.toggleCapabilityVisibility(${server.id}, ${index}, 'prompts')">
                            <span class="capability-toggle ${promptsExpanded ? 'expanded' : ''}" id="prompts-toggle-${index}">${promptsExpanded ? '▼' : '▶'}</span>
                            Available Prompts
                            <span class="capability-count">${server.prompt_details?.length || 0}</span>
                        </div>
                        <div class="capability-content ${promptsExpanded ? 'expanded' : ''}" id="prompts-content-${index}">
                            ${this.renderPrompts(server.prompt_details || [])}
                        </div>
                    </div>
                    
                    <div class="capability-section">
                        <div class="capability-header" onclick="serversTab.toggleCapabilityVisibility(${server.id}, ${index}, 'resources')">
                            <span class="capability-toggle ${resourcesExpanded ? 'expanded' : ''}" id="resources-toggle-${index}">${resourcesExpanded ? '▼' : '▶'}</span>
                            Available Resources
                            <span class="capability-count">${server.resource_details?.length || 0}</span>
                        </div>
                        <div class="capability-content ${resourcesExpanded ? 'expanded' : ''}" id="resources-content-${index}">
                            ${this.renderResources(server.resource_details || [])}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getAuthInfo(server) {
        if (!server.auth_type || server.type !== 'http') return '';
        const authMap = {
            'bearer': 'Auth: Bearer Token',
            'basic': `Auth: Basic (${this.adminPanel.escapeHtml(server.auth_username || 'Unknown')})`,
            'api-key': `Auth: API Key (${this.adminPanel.escapeHtml(server.auth_header_name || 'X-API-Key')})`
        };
        return `<span>${authMap[server.auth_type] || `Auth: ${this.adminPanel.escapeHtml(server.auth_type)}`}</span>`;
    }

    renderTools(toolDetails, serverId, serverType) {
        if (toolDetails.length === 0) {
            return '<div class="no-tools">No tools available</div>';
        }
        
        // Sort tools alphabetically by name
        const sortedTools = [...toolDetails].sort((a, b) => a.name.localeCompare(b.name));
        
        const toolRows = sortedTools.map(tool => {
            const isBlocked = tool.blocked || false;
            const toggleId = `tool-toggle-${serverId}-${tool.name.replace(/[^a-zA-Z0-9]/g, '_')}`;
            
            return `
                <tr>
                    <td class="tool-name">${this.adminPanel.escapeHtml(tool.name)}</td>
                    <td class="tool-description">${this.adminPanel.escapeHtml(tool.description || 'No description available')}</td>
                    <td class="tool-toggle-cell">
                        <label class="tool-toggle-switch">
                            <input type="checkbox" 
                                   id="${toggleId}" 
                                   ${!isBlocked ? 'checked' : ''} 
                                   onchange="serversTab.toggleToolBlock(${serverId}, '${serverType}', '${this.adminPanel.escapeHtml(tool.name)}', this.checked)">
                            <span class="tool-toggle-slider"></span>
                        </label>
                        <span class="tool-toggle-label">${isBlocked ? 'Blocked' : 'Enabled'}</span>
                    </td>
                </tr>
            `;
        }).join('');
        
        return `
            <table class="tools-table">
                <thead><tr><th>Tool Name</th><th>Description</th><th>Status</th></tr></thead>
                <tbody>${toolRows}</tbody>
            </table>
        `;
    }

    renderPrompts(promptDetails) {
        if (promptDetails.length === 0) {
            return '<div class="no-prompts">No prompts available</div>';
        }
        
        // Sort prompts alphabetically by name
        const sortedPrompts = [...promptDetails].sort((a, b) => a.name.localeCompare(b.name));
        
        const promptRows = sortedPrompts.map(prompt => `
            <tr>
                <td class="prompt-name">${this.adminPanel.escapeHtml(prompt.name)}</td>
                <td class="prompt-description">${this.adminPanel.escapeHtml(prompt.description || 'No description available')}</td>
            </tr>
        `).join('');
        
        return `
            <table class="prompts-table">
                <thead><tr><th>Prompt Name</th><th>Description</th></tr></thead>
                <tbody>${promptRows}</tbody>
            </table>
        `;
    }

    renderResources(resourceDetails) {
        if (resourceDetails.length === 0) {
            return '<div class="no-resources">No resources available</div>';
        }
        
        // Sort resources alphabetically by name
        const sortedResources = [...resourceDetails].sort((a, b) => a.name.localeCompare(b.name));
        
        const resourceRows = sortedResources.map(resource => `
            <tr>
                <td class="resource-name">${this.adminPanel.escapeHtml(resource.name)}</td>
                <td class="resource-description">${this.adminPanel.escapeHtml(resource.description || 'No description available')}</td>
                <td class="resource-uri">${this.adminPanel.escapeHtml(resource.uri || 'No URI available')}</td>
            </tr>
        `).join('');
        
        return `
            <table class="resources-table">
                <thead><tr><th>Resource Name</th><th>Description</th><th>URI</th></tr></thead>
                <tbody>${resourceRows}</tbody>
            </table>
        `;
    }

    // Capability visibility toggle
    toggleCapabilityVisibility(serverId, serverIndex, capability) {
        const content = document.getElementById(`${capability}-content-${serverIndex}`);
        const toggle = document.getElementById(`${capability}-toggle-${serverIndex}`);
        
        content.classList.toggle('expanded');
        toggle.textContent = content.classList.contains('expanded') ? '▼' : '▶';
        toggle.classList.toggle('expanded');
        
        // Save the expanded state using server ID (not index)
        const key = `${serverId}-${capability}`;
        this.expandedStates.set(key, content.classList.contains('expanded'));
    }

    // Tool blocking/unblocking functionality
    async toggleToolBlock(serverId, serverType, toolName, isEnabled) {
        try {
            const toggleData = {
                server_id: serverId,
                type: serverType,
                tool_name: toolName,
                block: !isEnabled // if enabled=true, we want to unblock (block=false)
            };

            const response = await this.makeRequest('/api/blocked-tools/toggle', 'POST', toggleData);
            
            // Update the toggle label
            const toggleId = `tool-toggle-${serverId}-${toolName.replace(/[^a-zA-Z0-9]/g, '_')}`;
            const toggleElement = document.getElementById(toggleId);
            if (toggleElement) {
                const labelElement = toggleElement.parentElement.nextElementSibling;
                if (labelElement && labelElement.classList.contains('tool-toggle-label')) {
                    labelElement.textContent = isEnabled ? 'Enabled' : 'Blocked';
                }
            }
            
        } catch (error) {
            console.error('Error toggling tool block:', error);
            
            // Revert the toggle state on error
            const toggleId = `tool-toggle-${serverId}-${toolName.replace(/[^a-zA-Z0-9]/g, '_')}`;
            const toggleElement = document.getElementById(toggleId);
            if (toggleElement) {
                toggleElement.checked = !isEnabled;
            }
            
            this.showError('Failed to toggle tool: ' + error.message);
        }
    }

    // Form and Modal Handling
    showModal(title) {
        document.getElementById('modalTitle').textContent = title;
        document.getElementById('serverModal').style.display = 'block';
    }

    closeModal() {
        document.getElementById('serverModal').style.display = 'none';
        this.clearFormError();
    }

    async handleFormSubmit() {
        try {
            const serverData = this.collectFormData();
            const url = this.currentEditingId 
                ? `/api/upstream-servers/${this.currentEditingId}`
                : '/api/upstream-servers';
            const method = this.currentEditingId ? 'PUT' : 'POST';
            
            await this.makeRequest(url, method, serverData);
            this.closeModal();
            await this.refreshData();
        } catch (error) {
            this.showFormError(error.message);
        }
    }

    showFormError(message) {
        // Display error message directly from backend - no interpretation needed
        console.log('Showing server form error:', message);
        
        const errorDiv = document.getElementById('serverFormError');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            errorDiv.classList.remove('hidden');
            // Scroll the error into view
            errorDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            console.error('Server form error div not found, using alert fallback');
            // Fallback to alert if error div doesn't exist
            alert('Error saving server: ' + message);
        }
    }

    clearFormError() {
        const errorDiv = document.getElementById('serverFormError');
        if (errorDiv) {
            errorDiv.style.display = 'none';
            errorDiv.classList.add('hidden');
            errorDiv.textContent = '';
        }
    }

    collectFormData() {
        const serverType = document.getElementById('serverType').value;
        const serverData = {
            name: document.getElementById('serverName').value,
            type: serverType,
            timeout: document.getElementById('serverTimeout').value,
            prefix: document.getElementById('serverPrefix').value,
            description: document.getElementById('serverDescription').value,
            enabled: document.getElementById('serverEnabled').checked
        };

        if (serverType === 'stdio') {
            serverData.command = this.parseCommand(document.getElementById('serverCommand').value);
            serverData.url = '';
        } else {
            serverData.url = document.getElementById('serverUrl').value;
        }

        if (serverType === 'http') {
            const auth = this.collectAuthData();
            if (auth) serverData.auth = auth;
        }
        
        return serverData;
    }

    parseCommand(commandString) {
        const trimmed = commandString.trim();
        if (!trimmed) return [];
        return trimmed.match(/(?:[^\s"]+|"[^"]*")+/g)?.map(arg => 
            arg.startsWith('"') && arg.endsWith('"') ? arg.slice(1, -1) : arg
        ) || [];
    }

    collectAuthData() {
        const authType = document.getElementById('authType').value;
        if (!authType) return null;

        const auth = { type: authType };
        const collectors = {
            bearer: () => ({ bearer_token: document.getElementById('bearerToken').value }),
            basic: () => ({
                username: document.getElementById('basicUsername').value,
                password: document.getElementById('basicPassword').value
            }),
            'api-key': () => ({
                api_key: document.getElementById('apiKey').value,
                header_name: document.getElementById('apiKeyHeader').value || 'X-API-Key'
            })
        };
        
        return { ...auth, ...(collectors[authType]?.() || {}) };
    }

    resetForm() {
        document.getElementById('serverForm').reset();
        document.getElementById('serverEnabled').checked = true;
        this.resetAuthFields();
        this.toggleServerFields();
        this.toggleAuthFields();
    }

    populateForm(server) {
        const fields = {
            serverName: server.name || '',
            serverUrl: server.url || '',
            serverType: server.type || 'websocket',
            serverTimeout: server.timeout || '30s',
            serverPrefix: server.prefix || '',
            serverDescription: server.description || '',
            serverEnabled: server.enabled
        };

        Object.entries(fields).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.type === 'checkbox' ? (element.checked = value) : (element.value = value);
            }
        });

        if (server.command?.length > 0) {
            document.getElementById('serverCommand').value = server.command.join(' ');
        }

        this.populateAuthFields(server);
        this.toggleServerFields();
        this.toggleAuthFields();
    }

    populateAuthFields(server) {
        if (!server.auth_type) {
            this.resetAuthFields();
            return;
        }

        document.getElementById('authType').value = server.auth_type;
        
        const authPopulators = {
            bearer: () => document.getElementById('bearerToken').value = server.auth_token || '',
            basic: () => {
                document.getElementById('basicUsername').value = server.auth_username || '';
                document.getElementById('basicPassword').value = server.auth_password || '';
            },
            'api-key': () => {
                document.getElementById('apiKey').value = server.auth_api_key || '';
                document.getElementById('apiKeyHeader').value = server.auth_header_name || 'X-API-Key';
            }
        };
        
        authPopulators[server.auth_type]?.();
    }

    resetAuthFields() {
        const authFields = { authType: '', bearerToken: '', basicUsername: '', basicPassword: '', apiKey: '', apiKeyHeader: 'X-API-Key' };
        Object.entries(authFields).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.value = value;
        });
    }

    toggleServerFields() {
        const serverType = document.getElementById('serverType').value;
        const elements = {
            urlGroup: document.getElementById('urlGroup'),
            commandGroup: document.getElementById('commandGroup'),
            authSection: document.getElementById('authSection'),
            serverUrl: document.getElementById('serverUrl'),
            serverCommand: document.getElementById('serverCommand')
        };
        
        if (serverType === 'stdio') {
            elements.urlGroup.classList.add('hidden');
            elements.commandGroup.classList.remove('hidden');
            elements.authSection.classList.remove('visible');
            elements.serverUrl.required = false;
            elements.serverCommand.required = true;
        } else {
            elements.urlGroup.classList.remove('hidden');
            elements.commandGroup.classList.add('hidden');
            elements.serverUrl.required = true;
            elements.serverCommand.required = false;
            
            if (serverType === 'http') {
                elements.authSection.classList.add('visible');
            } else {
                elements.authSection.classList.remove('visible');
            }
        }
    }

    toggleAuthFields() {
        const authType = document.getElementById('authType').value;
        
        // Hide all auth fields
        Object.values(AUTH_TYPES).forEach(config => {
            document.getElementById(config.fields).classList.remove('active');
        });
        
        // Show relevant auth fields
        if (AUTH_TYPES[authType]) {
            document.getElementById(AUTH_TYPES[authType].fields).classList.add('active');
        }
    }

    // Connected-only toggle functionality
    toggleConnectedOnly() {
        this.connectedOnlyMode = !this.connectedOnlyMode;
        
        // Update toggle visual state
        const toggle = document.getElementById('connectedOnlyToggle');
        if (toggle) {
            if (this.connectedOnlyMode) {
                toggle.classList.add('active');
            } else {
                toggle.classList.remove('active');
            }
        }
        
        // Apply filters and re-render
        this.applyFilters();
    }

    applyFilters() {
        let servers = [...this.allServers];
        
        // Apply connected-only filter first
        if (this.connectedOnlyMode) {
            servers = servers.filter(server => 
                server.enabled && (server.runtime_connected || server.status === 'connected')
            );
        }
        
        // Apply search filter
        if (this.searchTerm) {
            servers = servers.filter(server => 
                server.name.toLowerCase().includes(this.searchTerm)
            );
        }
        
        this.filteredServers = servers;
        this.renderServers(this.filteredServers);
        this.updateServerCountWithFilters();
    }

    updateServerCountWithFilters() {
        const totalCount = this.allServers.length;
        const filteredCount = this.filteredServers.length;
        
        let countText = '';
        
        if (this.connectedOnlyMode && this.searchTerm) {
            countText = `${filteredCount}/${totalCount} servers`;
        } else if (this.connectedOnlyMode) {
            countText = `${filteredCount}/${totalCount} servers`;
        } else if (this.searchTerm) {
            countText = `${filteredCount}/${totalCount} servers`;
        } else {
            countText = `${totalCount} servers`;
        }
        
        document.getElementById('serverCount').textContent = countText;
    }
}
