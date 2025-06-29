// MCP Gateway Admin Panel JavaScript

class AdminPanel {
    constructor() {
        // Check if auth is enabled (injected by server)
        this.authEnabled = window.AUTH_ENABLED || false;
        this.token = null;
        this.user = null;
        
        // Auto-refresh configuration
        this.autoRefreshEnabled = true;
        this.autoRefreshInterval = 5000; // 5 seconds
        this.autoRefreshTimer = null;
        this.lastRefreshTime = 0;
        this.isRefreshing = false;
        
        // Cache for preventing unnecessary DOM updates
        
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
        
        // Initialize servers tab
        this.serversTab = new ServersTab(this);
        
        // Initialize curated servers management
        this.curatedServerManager = new CuratedServerManager(this);
        // Make curatedServerManager globally accessible for onclick handlers
        window.curatedServerManager = this.curatedServerManager;
        
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
            this.loadServersHTML(),
            this.loadCuratedServersHTML(),
            ...(this.authEnabled ? [this.loadUsersHTML(), this.loadTokensHTML()] : [])
        ]);
        
        // Initialize components after HTML is loaded
        await this.serversTab.initialize();
        
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

    async loadServersHTML() {
        try {
            const response = await fetch('/static/servers.html');
            const html = await response.text();
            document.getElementById('serversTabPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading servers HTML:', error);
        }
    }

    async loadCuratedServersHTML() {
        try {
            const response = await fetch('/static/curated-servers.html');
            const html = await response.text();
            document.getElementById('curatedServersTabPlaceholder').innerHTML = html;
        } catch (error) {
            console.error('Error loading curated servers HTML:', error);
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
            case 'curated-servers':
                await this.ensureCuratedServersTabLoaded();
                const curatedServersTab = document.getElementById('curatedServersTab');
                if (curatedServersTab) {
                    curatedServersTab.classList.remove('hidden');
                    // Initialize and load curated servers when switching to tab
                    if (this.curatedServerManager) {
                        await this.curatedServerManager.init();
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

    async ensureCuratedServersTabLoaded() {
        if (!document.getElementById('curatedServersTab')) {
            await this.loadCuratedServersHTML();
        }
    }

    async ensureCuratedServersTabLoaded() {
        if (!document.getElementById('curatedServersTab')) {
            await this.loadCuratedServersHTML();
        }
    }

    async loadInitialData() {
        await this.statisticsTab.loadStats();
        await this.serversTab.loadServers();
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
                    this.serversTab.loadServers(true) // Skip indicator since we're already showing it
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
        if (this.statisticsTab) {
            this.statisticsTab.clearCache();
        }
        if (this.serversTab) {
            this.serversTab.lastServersData = null;
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
let serversTab;
let userManager;
let tokenManager;

document.addEventListener('DOMContentLoaded', function() {
    adminPanel = new AdminPanel();
    window.adminPanel = adminPanel; // Make adminPanel globally accessible
    
    // Make serversTab globally accessible once it's initialized
    setTimeout(() => {
        if (adminPanel.serversTab) {
            serversTab = adminPanel.serversTab;
            window.serversTab = serversTab;
        }
    }, 100);
    
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

// Global functions for button handlers
function openChangePasswordPage() {
    window.location.href = '/ui/change-password';
}
