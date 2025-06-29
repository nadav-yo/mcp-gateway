// User-specific Curated Server Manager (read-only)
class CuratedServerUserManager {
    constructor(authConfig) {
        this.authEnabled = authConfig.authEnabled;
        this.token = authConfig.token;
        this.copyToClipboard = authConfig.copyToClipboard;
        this.curatedServers = [];
    }

    async init() {
        await this.loadCuratedServers();
    }

    async loadCuratedServers() {
        try {
            const response = await this.makeRequest('/api/curated-servers', 'GET');
            
            if (response.ok) {
                const data = await response.json();
                this.curatedServers = data.data || [];
                this.renderCuratedServers();
                this.updateServerCount();
            } else {
                const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
                this.showError(`Failed to load curated servers: ${errorData.message || response.statusText}`);
            }
        } catch (error) {
            console.error('Error loading curated servers:', error);
            this.showError('Failed to load curated servers: ' + error.message);
        }
    }

    renderCuratedServers() {
        const serversList = document.getElementById('curatedServersUserList');
        if (!serversList) {
            console.error('curatedServersUserList element not found');
            return;
        }

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
                    <button class="btn btn-sm btn-secondary copy-config-btn" onclick="curatedServerUserManager.copyServerConfig(${server.id})" title="Copy MCP config">Copy</button>
                </td>
            </tr>
        `;
    }

    getTypeLabel(type) {
        switch (type) {
            case 'stdio': return 'STDIO';
            case 'http': return 'HTTP';
            case 'ws': return 'WebSocket';
            default: return type.toUpperCase();
        }
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

    copyServerConfig(serverId) {
        const server = this.curatedServers.find(s => s.id == serverId);
        if (!server) {
            console.error('Server not found:', serverId);
            return;
        }

        const configText = this.generateMCPConfig(server);
        
        // Find the button that was clicked
        const buttons = document.querySelectorAll('.copy-config-btn');
        const button = Array.from(buttons).find(btn => 
            btn.getAttribute('onclick').includes(serverId)
        );

        if (this.copyToClipboard) {
            this.copyToClipboard(configText, button);
        } else {
            // Fallback copy method
            navigator.clipboard.writeText(configText).then(() => {
                if (button) {
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    button.style.background = '#28a745';
                    
                    setTimeout(() => {
                        button.textContent = originalText;
                        button.style.background = '';
                    }, 2000);
                }
            }).catch(err => {
                console.error('Failed to copy configuration:', err);
            });
        }
    }

    updateServerCount() {
        const countElement = document.getElementById('curatedServerUserCount');
        if (countElement) {
            countElement.textContent = `${this.curatedServers.length} curated servers`;
        }
    }

    async makeRequest(url, method = 'GET', data = null) {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        // Add auth token if available
        if (this.authEnabled && this.token) {
            options.headers['Authorization'] = `Bearer ${this.token}`;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        return fetch(url, options);
    }

    showError(message) {
        const errorDiv = document.getElementById('curatedServerUserError');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.classList.remove('hidden');
            setTimeout(() => errorDiv.classList.add('hidden'), 5000);
        }
        console.error('Curated Server User Manager Error:', message);
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}
