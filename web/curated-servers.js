// Curated Servers Management JavaScript

class CuratedServerManager {
    constructor(adminPanel) {
        this.adminPanel = adminPanel;
        this.curatedServers = [];
    }

    async init() {
        this.setupEventListeners();
        await this.loadCuratedServers();
    }

    setupEventListeners() {
        // Add curated server form
        const addForm = document.getElementById('addCuratedServerForm');
        if (addForm) {
            addForm.addEventListener('submit', (e) => this.handleAddCuratedServer(e));
        }

        // Edit curated server form
        const editForm = document.getElementById('editCuratedServerForm');
        if (editForm) {
            editForm.addEventListener('submit', (e) => this.handleEditCuratedServer(e));
        }
    }

    async loadCuratedServers() {
        try {
            const response = await this.makeRequest('/api/curated-servers', 'GET');
            if (response.ok) {
                const apiResponse = await response.json();
                
                // Handle the API response format { success: true, data: [...] }
                if (apiResponse.success) {
                    // Handle null/undefined data (no servers) or array data
                    this.curatedServers = Array.isArray(apiResponse.data) ? apiResponse.data : [];
                } else {
                    console.error('API response indicates failure:', apiResponse);
                    this.curatedServers = [];
                }
                
                this.renderCuratedServers();
                this.updateCuratedServerCount();
            } else {
                const errorText = await response.text();
                throw new Error(`Failed to load curated servers: ${response.status} - ${errorText}`);
            }
        } catch (error) {
            console.error('Error loading curated servers:', error);
            this.curatedServers = []; // Ensure it's always an array
            this.renderCuratedServers();
            this.showError(`Failed to load curated servers: ${error.message}`);
        }
    }

    renderCuratedServers() {
        const serversList = document.getElementById('curatedServersList');
        if (!serversList) return;

        // Ensure we have an array
        if (!Array.isArray(this.curatedServers)) {
            console.warn('curatedServers is not an array:', this.curatedServers);
            this.curatedServers = [];
        }

        if (this.curatedServers.length === 0) {
            serversList.innerHTML = '<div class="no-data">No curated servers found</div>';
            return;
        }

        const serversTableHTML = `
            <table class="servers-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Command/URL</th>
                        <th>Description</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${this.curatedServers.map(server => this.renderCuratedServerRow(server)).join('')}
                </tbody>
            </table>
        `;
        serversList.innerHTML = serversTableHTML;
    }

    renderCuratedServerRow(server) {
        const createdDate = new Date(server.created_at).toLocaleDateString();
        const commandOrUrl = server.type === 'stdio' ? server.command : server.url;
        const description = server.description || 'No description';
        const typeLabel = this.getTypeLabel(server.type);

        // Check if we're in admin mode (has full admin panel) or user mode
        const isAdminMode = this.adminPanel && this.adminPanel.userManager !== undefined;

        return `
            <tr>
                <td class="server-name-cell">
                    <strong>${server.name}</strong>
                </td>
                <td>
                    <span class="server-type-badge ${server.type}">${typeLabel}</span>
                </td>
                <td class="command-cell">
                    <code>${commandOrUrl}</code>
                    ${server.args && server.args.length > 0 ? 
                        `<br><small class="args-preview">Args: ${server.args.slice(0, 2).join(', ')}${server.args.length > 2 ? '...' : ''}</small>` 
                        : ''}
                </td>
                <td class="description-cell">
                    ${description.length > 100 ? description.substring(0, 100) + '...' : description}
                </td>
                <td>${createdDate}</td>
                <td class="server-actions-cell">
                    <button class="btn btn-sm btn-secondary" onclick="copyCuratedServerConfig(${server.id})" title="Copy MCP config">Copy</button>
                    ${isAdminMode ? `
                        <button class="btn btn-sm btn-secondary" onclick="editCuratedServer(${server.id})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteCuratedServer(${server.id}, '${server.name}')">Delete</button>
                    ` : ''}
                </td>
            </tr>
        `;
    }

    generateMCPConfig(server) {
        let serverConfig = {};
        
        if (server.type === 'stdio') {
            // Parse command and args
            const command = server.command || '';
            const args = server.args || [];
            
            // Split the command into words
            const commandWords = command.trim().split(/\s+/).filter(word => word.length > 0);
            
            // First word is the actual command
            const actualCommand = commandWords.length > 0 ? commandWords[0] : '';
            
            // Everything else from command goes into args, plus the original args
            const commandArgs = commandWords.slice(1); // All words after the first
            const allArgs = [...commandArgs, ...args]; // Combine command args with original args
            
            serverConfig = {
                command: actualCommand,
                args: allArgs
            };
        } else {
            // HTTP or WebSocket server
            serverConfig = {
                url: server.url || ''
            };
        }
        
        // Format as just the server entry without outer braces
        const formattedConfig = `    "${server.name}": ${JSON.stringify(serverConfig, null, 8).replace(/\n/g, '\n    ')}`;
        return formattedConfig;
    }

    getTypeLabel(type) {
        const typeLabels = {
            'stdio': 'STDIO',
            'http': 'HTTP',
            'ws': 'WebSocket'
        };
        return typeLabels[type] || type.toUpperCase();
    }

    updateCuratedServerCount() {
        const countElement = document.getElementById('curatedServerCount');
        if (countElement) {
            countElement.textContent = `${this.curatedServers.length} curated servers`;
        }
    }

    async handleAddCuratedServer(e) {
        e.preventDefault();
        
        this.clearFormError('add');
        
        const formData = this.getFormData('add');
        
        try {
            const response = await this.makeRequest('/api/curated-servers', 'POST', formData);
            
            if (response.ok) {
                const apiResponse = await response.json();
                if (apiResponse.success && apiResponse.data) {
                    this.showSuccess(`Curated server "${apiResponse.data.name}" created successfully`);
                    closeAddCuratedServerModal();
                    await this.loadCuratedServers();
                } else {
                    throw new Error(apiResponse.error || 'Failed to create curated server');
                }
            } else {
                const errorData = await response.text();
                throw new Error(errorData || `Failed to create curated server: ${response.status}`);
            }
        } catch (error) {
            console.error('Error creating curated server:', error);
            this.showFormError('add', error.message || 'Failed to create curated server');
        }
    }

    async handleEditCuratedServer(e) {
        e.preventDefault();
        
        this.clearFormError('edit');
        
        const serverId = document.getElementById('editCuratedServerId').value;
        const formData = this.getFormData('edit');
        
        try {
            const response = await this.makeRequest(`/api/curated-servers/${serverId}`, 'PUT', formData);
            
            if (response.ok) {
                const apiResponse = await response.json();
                if (apiResponse.success && apiResponse.data) {
                    this.showSuccess(`Curated server "${apiResponse.data.name}" updated successfully`);
                    closeEditCuratedServerModal();
                    await this.loadCuratedServers();
                } else {
                    throw new Error(apiResponse.error || 'Failed to update curated server');
                }
            } else {
                const errorData = await response.text();
                throw new Error(errorData || `Failed to update curated server: ${response.status}`);
            }
        } catch (error) {
            console.error('Error updating curated server:', error);
            this.showFormError('edit', error.message || 'Failed to update curated server');
        }
    }

    getFormData(mode) {
        const prefix = mode === 'add' ? 'addCuratedServer' : 'editCuratedServer';
        
        const type = document.getElementById(`${prefix}Type`).value;
        const name = document.getElementById(`${prefix}Name`).value;
        const description = document.getElementById(`${prefix}Description`).value;
        
        const formData = {
            name: name,
            type: type,
            description: description
        };

        if (type === 'stdio') {
            formData.command = document.getElementById(`${prefix}Command`).value;
            const argsText = document.getElementById(`${prefix}Args`).value;
            formData.args = argsText.split('\n').filter(arg => arg.trim()).map(arg => arg.trim());
            formData.url = '';
        } else {
            formData.url = document.getElementById(`${prefix}Url`).value;
            formData.command = '';
            formData.args = [];
        }

        return formData;
    }

    async deleteCuratedServer(serverId, serverName) {
        if (!confirm(`Are you sure you want to delete curated server "${serverName}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await this.makeRequest(`/api/curated-servers/${serverId}`, 'DELETE');
            
            if (response.ok) {
                const apiResponse = await response.json();
                if (apiResponse.success) {
                    this.showSuccess(`Curated server "${serverName}" deleted successfully`);
                    await this.loadCuratedServers();
                } else {
                    throw new Error(apiResponse.error || 'Failed to delete curated server');
                }
            } else {
                const errorData = await response.text();
                throw new Error(errorData || `Failed to delete curated server: ${response.status}`);
            }
        } catch (error) {
            console.error('Error deleting curated server:', error);
            this.showError(error.message || 'Failed to delete curated server');
        }
    }

    async editCuratedServer(serverId) {
        const server = this.curatedServers.find(s => s.id === serverId);
        if (!server) {
            this.showError('Curated server not found');
            return;
        }

        // Populate edit form
        document.getElementById('editCuratedServerId').value = server.id;
        document.getElementById('editCuratedServerName').value = server.name;
        document.getElementById('editCuratedServerType').value = server.type;
        document.getElementById('editCuratedServerDescription').value = server.description || '';

        if (server.type === 'stdio') {
            document.getElementById('editCuratedServerCommand').value = server.command || '';
            document.getElementById('editCuratedServerArgs').value = (server.args || []).join('\n');
            document.getElementById('editCuratedServerUrl').value = '';
        } else {
            document.getElementById('editCuratedServerUrl').value = server.url || '';
            document.getElementById('editCuratedServerCommand').value = '';
            document.getElementById('editCuratedServerArgs').value = '';
        }

        // Handle type-specific field visibility
        handleEditCuratedServerTypeChange();

        // Show modal
        document.getElementById('editCuratedServerModal').style.display = 'block';
    }

    async makeRequest(url, method = 'GET', data = null) {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        // Add auth token if available
        if (this.adminPanel.authEnabled && this.adminPanel.token) {
            options.headers['Authorization'] = `Bearer ${this.adminPanel.token}`;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        return fetch(url, options);
    }

    showError(message) {
        const errorDiv = document.getElementById('curatedServerError');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.classList.remove('hidden');
            setTimeout(() => errorDiv.classList.add('hidden'), 5000);
        }
    }

    showSuccess(message) {
        const successDiv = document.getElementById('curatedServerSuccess');
        if (successDiv) {
            successDiv.textContent = message;
            successDiv.classList.remove('hidden');
            setTimeout(() => successDiv.classList.add('hidden'), 3000);
        }
    }

    showFormError(mode, message) {
        const errorDiv = document.getElementById(`${mode}CuratedServerFormError`);
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            errorDiv.classList.remove('hidden');
            errorDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            this.showError(message);
        }
    }

    clearFormError(mode) {
        const errorDiv = document.getElementById(`${mode}CuratedServerFormError`);
        if (errorDiv) {
            errorDiv.style.display = 'none';
            errorDiv.classList.add('hidden');
            errorDiv.textContent = '';
        }
    }
}

// Global functions for modal management
function showAddCuratedServerModal() {
    document.getElementById('addCuratedServerForm').reset();
    
    // Clear any previous form errors
    if (window.curatedServerManager) {
        window.curatedServerManager.clearFormError('add');
    } else if (window.adminPanel && window.adminPanel.curatedServerManager) {
        window.adminPanel.curatedServerManager.clearFormError('add');
    }
    
    // Set default type to HTTP and show appropriate fields
    document.getElementById('addCuratedServerType').value = 'http';
    document.getElementById('addCuratedServerUrlGroup').style.display = 'block';
    document.getElementById('addCuratedServerCommandGroup').style.display = 'none';
    document.getElementById('addCuratedServerArgsGroup').style.display = 'none';
    document.getElementById('addCuratedServerUrl').required = true;
    document.getElementById('addCuratedServerCommand').required = false;
    
    document.getElementById('addCuratedServerModal').style.display = 'block';
}

function closeAddCuratedServerModal() {
    document.getElementById('addCuratedServerModal').style.display = 'none';
}

function closeEditCuratedServerModal() {
    document.getElementById('editCuratedServerModal').style.display = 'none';
}

function handleCuratedServerTypeChange() {
    const type = document.getElementById('addCuratedServerType').value;
    const urlGroup = document.getElementById('addCuratedServerUrlGroup');
    const commandGroup = document.getElementById('addCuratedServerCommandGroup');
    const argsGroup = document.getElementById('addCuratedServerArgsGroup');

    if (type === 'stdio') {
        urlGroup.style.display = 'none';
        commandGroup.style.display = 'block';
        argsGroup.style.display = 'block';
        document.getElementById('addCuratedServerUrl').required = false;
        document.getElementById('addCuratedServerCommand').required = true;
    } else if (type === 'http' || type === 'ws') {
        urlGroup.style.display = 'block';
        commandGroup.style.display = 'none';
        argsGroup.style.display = 'none';
        document.getElementById('addCuratedServerUrl').required = true;
        document.getElementById('addCuratedServerCommand').required = false;
    }
}

function handleEditCuratedServerTypeChange() {
    const type = document.getElementById('editCuratedServerType').value;
    const urlGroup = document.getElementById('editCuratedServerUrlGroup');
    const commandGroup = document.getElementById('editCuratedServerCommandGroup');
    const argsGroup = document.getElementById('editCuratedServerArgsGroup');

    if (type === 'stdio') {
        urlGroup.style.display = 'none';
        commandGroup.style.display = 'block';
        argsGroup.style.display = 'block';
        document.getElementById('editCuratedServerUrl').required = false;
        document.getElementById('editCuratedServerCommand').required = true;
    } else if (type === 'http' || type === 'ws') {
        urlGroup.style.display = 'block';
        commandGroup.style.display = 'none';
        argsGroup.style.display = 'none';
        document.getElementById('editCuratedServerUrl').required = true;
        document.getElementById('editCuratedServerCommand').required = false;
    }
}

// Wrapper functions for safe curatedServerManager access
async function reloadCuratedServers() {
    try {
        let manager = null;
        
        if (window.curatedServerManager) {
            manager = window.curatedServerManager;
        } else if (window.adminPanel && window.adminPanel.curatedServerManager) {
            manager = window.adminPanel.curatedServerManager;
        }
        
        if (manager) {
            await manager.loadCuratedServers();
        } else {
            console.error('Curated server manager not available');
            alert('Curated server management is not available. Please refresh the page.');
        }
    } catch (error) {
        console.error('Error reloading curated servers:', error);
        alert('Failed to reload curated servers: ' + error.message);
    }
}

async function deleteCuratedServer(serverId, serverName) {
    try {
        let manager = null;
        
        if (window.curatedServerManager) {
            manager = window.curatedServerManager;
        } else if (window.adminPanel && window.adminPanel.curatedServerManager) {
            manager = window.adminPanel.curatedServerManager;
        }
        
        if (manager) {
            await manager.deleteCuratedServer(serverId, serverName);
        } else {
            console.error('Curated server manager not available');
            alert('Curated server management is not available. Please refresh the page.');
        }
    } catch (error) {
        console.error('Error deleting curated server:', error);
        alert('Failed to delete curated server: ' + error.message);
    }
}

async function editCuratedServer(serverId) {
    try {
        let manager = null;
        
        if (window.curatedServerManager) {
            manager = window.curatedServerManager;
        } else if (window.adminPanel && window.adminPanel.curatedServerManager) {
            manager = window.adminPanel.curatedServerManager;
        }
        
        if (manager) {
            await manager.editCuratedServer(serverId);
        } else {
            console.error('Curated server manager not available');
            alert('Curated server management is not available. Please refresh the page.');
        }
    } catch (error) {
        console.error('Error editing curated server:', error);
        alert('Failed to edit curated server: ' + error.message);
    }
}

async function copyCuratedServerConfig(serverId) {
    try {
        let manager = null;
        
        if (window.curatedServerManager) {
            manager = window.curatedServerManager;
        } else if (window.adminPanel && window.adminPanel.curatedServerManager) {
            manager = window.adminPanel.curatedServerManager;
        }
        
        if (manager) {
            const server = manager.curatedServers.find(s => s.id === serverId);
            if (server) {
                const config = manager.generateMCPConfig(server);
                
                // Find the copy button that was clicked
                const button = event.target;
                
                // Use the admin panel's copy functionality
                if (window.adminPanel && window.adminPanel.copyToClipboard) {
                    window.adminPanel.copyToClipboard(config, button);
                } else {
                    // Fallback copy method
                    navigator.clipboard.writeText(config).then(() => {
                        const originalText = button.textContent;
                        button.textContent = 'Copied!';
                        button.style.background = '#28a745';
                        
                        setTimeout(() => {
                            button.textContent = originalText;
                            button.style.background = '';
                        }, 2000);
                    }).catch(err => {
                        console.error('Failed to copy config:', err);
                        alert('Failed to copy configuration to clipboard');
                    });
                }
            } else {
                alert('Curated server not found');
            }
        } else {
            console.error('Curated server manager not available');
            alert('Curated server management is not available. Please refresh the page.');
        }
    } catch (error) {
        console.error('Error copying curated server config:', error);
        alert('Failed to copy curated server config: ' + error.message);
    }
}
