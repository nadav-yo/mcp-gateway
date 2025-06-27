// User Info Management Class

class UserInfoManager {
    constructor() {
        this.authEnabled = window.AUTH_ENABLED || false;
        this.user = null;
    }

    async getCurrentUser() {
        const token = localStorage.getItem('mcp_token');
        if (!token) return false;
        
        try {
            const response = await fetch('/auth/me', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const userData = await response.json();
                this.user = userData;
                this.updateUserInfo();
                return true;
            } else {
                throw new Error('Failed to get current user');
            }
        } catch (error) {
            console.error('Failed to get current user:', error);
            return false;
        }
    }

    updateUserInfo() {
        const userInfoDiv = document.getElementById('userInfo');
        const logoutBtn = document.getElementById('logoutBtn');
        
        if (this.authEnabled && this.user && userInfoDiv) {
            userInfoDiv.textContent = `Logged in as: ${this.user.username}`;
            userInfoDiv.classList.remove('hidden');
            
            if (logoutBtn) {
                logoutBtn.classList.remove('hidden');
            }
        } else if (!this.authEnabled && userInfoDiv) {
            userInfoDiv.textContent = 'Authentication disabled';
            userInfoDiv.classList.remove('hidden');
            
            if (logoutBtn) {
                logoutBtn.style.display = 'none';
            }
        }
    }

    async logout() {
        const token = localStorage.getItem('mcp_token');
        
        // Call server-side logout to revoke token
        if (token) {
            try {
                await fetch('/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.log('Logout API call failed:', error);
                // Continue with client-side logout even if server call fails
            }
        }
        
        // Clear client-side state
        this.user = null;
        localStorage.removeItem('mcp_token');
        
        // Clear cookie
        document.cookie = 'mcp_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=strict';
        
        // Redirect to login page
        window.location.href = '/ui/login';
    }

    setupEventListeners() {
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.logout());
        }
    }

    async initialize() {
        if (this.authEnabled) {
            await this.getCurrentUser();
        } else {
            this.updateUserInfo();
        }
        this.setupEventListeners();
    }
}
