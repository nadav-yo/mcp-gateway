// Token Management Class

class TokenManager {
    constructor(adminPanel) {
        this.adminPanel = adminPanel;
    }

    // Token management methods
    async loadTokens() {
        if (!this.adminPanel.authEnabled) return;
        
        try {
            // Add cache busting parameter
            const response = await this.adminPanel.makeAuthenticatedRequest(`/api/auth/tokens?_=${new Date().getTime()}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${await response.text()}`);
            }
            const tokens = await response.json();
            this.renderTokens(tokens);
        } catch (error) {
            console.error('Error loading tokens:', error);
            this.adminPanel.showError('tokenError', 'Failed to load tokens: ' + error.message);
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
                    <div class="token-description">${this.adminPanel.escapeHtml(token.description || 'No description')}</div>
                    <div class="token-meta">
                        Created: ${new Date(token.created_at).toLocaleDateString()}
                        ${token.expires_at ? ` | Expires: ${new Date(token.expires_at).toLocaleDateString()}` : ''}
                        ${token.last_used ? ` | Last used: ${new Date(token.last_used).toLocaleDateString()}` : ''}
                    </div>
                    <div class="token-meta">Token: ****...${token.token ? token.token.slice(-4) : '****'}</div>
                </div>
                <button class="btn btn-sm btn-danger" onclick="window.adminPanel.tokenManager.revokeToken(${token.id})">Revoke</button>
            </div>
        `).join('');
    }

    async createToken() {
        if (!this.adminPanel.authEnabled) return;
        
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
            const response = await this.adminPanel.makeAuthenticatedRequest('/api/auth/tokens', {
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
                        <button onclick="window.adminPanel.copyToClipboard('${tokenValue}', this)" style="padding: 4px 8px; background: #007AFF; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; white-space: nowrap;">
                            Copy
                        </button>
                    </div>
                    <div style="margin-top: 10px; color: #dc3545; font-weight: bold;">
                        ⚠️ This token will not be shown again. Please copy it now!
                    </div>
                `;
                this.adminPanel.showSuccess('tokenSuccess', successMessage);
                
                document.getElementById('createTokenForm').reset();
                await this.loadTokens();
            } else {
                const error = await response.text();
                this.adminPanel.showError('tokenError', error);
            }
        } catch (error) {
            this.adminPanel.showError('tokenError', 'Failed to create token: ' + error.message);
        }
    }

    async revokeToken(tokenId) {
        if (!this.adminPanel.authEnabled) return;
        
        if (!confirm('Are you sure you want to revoke this token?')) {
            return;
        }
        
        try {
            console.log('Revoking token ID:', tokenId);
            const response = await this.adminPanel.makeAuthenticatedRequest(`/api/auth/tokens/revoke?id=${tokenId}`, {
                method: 'DELETE'
            });
            
            console.log('Revoke response status:', response.status);
            
            if (response.ok) {
                console.log('Token revoked successfully, reloading token list...');
                this.adminPanel.showSuccess('tokenSuccess', 'Token revoked successfully');
                // Reload the tokens list immediately
                await this.loadTokens();
            } else {
                const errorText = await response.text();
                console.error('Revoke token error:', errorText);
                this.adminPanel.showError('tokenError', 'Failed to revoke token: ' + errorText);
            }
        } catch (error) {
            console.error('Revoke token exception:', error);
            this.adminPanel.showError('tokenError', 'Failed to revoke token: ' + error.message);
        }
    }
}
