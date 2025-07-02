// MCP Gateway Login Page JavaScript

class LoginPage {
    constructor() {
        this.form = document.getElementById('loginForm');
        this.errorDiv = document.getElementById('loginError');
        this.loginButton = document.getElementById('loginButton');
        this.loginContainer = document.getElementById('loginContainer');
        this.loadingMessage = document.getElementById('loadingMessage');
        this.noAuthMessage = document.getElementById('noAuthMessage');
        
        this.init();
    }
    
    init() {
        // Check if auth is enabled
        if (window.AUTH_ENABLED === false) {
            this.showNoAuthMessage();
            return;
        }
        
        // Show login form
        this.showLoginForm();
        
        // Add event listeners
        this.form.addEventListener('submit', (e) => this.handleLogin(e));
        
        // Focus username field
        document.getElementById('username').focus();
    }
    
    showLoginForm() {
        this.loadingMessage.classList.add('hidden');
        this.loginContainer.classList.remove('hidden');
    }
    
    showNoAuthMessage() {
        this.loadingMessage.classList.add('hidden');
        this.noAuthMessage.classList.remove('hidden');
    }
    
    showError(message) {
        this.errorDiv.textContent = message;
        this.errorDiv.classList.remove('hidden');
    }
    
    hideError() {
        this.errorDiv.classList.add('hidden');
    }
    
    setLoading(loading) {
        this.loginButton.disabled = loading;
        this.loginButton.textContent = loading ? 'Signing in...' : 'Sign In';
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        this.hideError();
        this.setLoading(true);
        
        const formData = new FormData(this.form);
        const credentials = {
            username: formData.get('username'),
            password: formData.get('password')
        };
        
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentials)
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Store the token in localStorage and as a cookie
                localStorage.setItem('mcp_token', data.token);
                document.cookie = `mcp_token=${data.token}; path=/; max-age=${24*60*60}; samesite=strict`;
                
                // Redirect based on user role
                if (data.user && data.user.is_admin) {
                    window.location.href = '/ui/admin';
                } else {
                    window.location.href = '/ui/user';
                }
            } else {
                const errorData = await response.text();
                this.showError(errorData || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showError('Network error. Please try again.');
        } finally {
            this.setLoading(false);
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new LoginPage();
});
