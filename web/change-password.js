// Password Change Management Class

class PasswordChanger {
    constructor() {
        this.form = null;
        this.errorDiv = null;
        this.successDiv = null;
    }

    initialize() {
        this.form = document.getElementById('changePasswordForm');
        this.errorDiv = document.getElementById('passwordError');
        this.successDiv = document.getElementById('passwordSuccess');
        
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        }

        const cancelBtn = document.getElementById('cancelBtn');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => this.handleCancel());
        }

        // Add real-time password confirmation validation
        const confirmPasswordInput = document.getElementById('confirmPassword');
        const newPasswordInput = document.getElementById('newPassword');
        
        if (confirmPasswordInput && newPasswordInput) {
            confirmPasswordInput.addEventListener('input', () => {
                this.validatePasswordMatch();
            });
            
            newPasswordInput.addEventListener('input', () => {
                this.validatePasswordMatch();
            });
        }
    }

    validatePasswordMatch() {
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const confirmInput = document.getElementById('confirmPassword');
        
        if (confirmPassword && newPassword !== confirmPassword) {
            confirmInput.setCustomValidity('Passwords do not match');
        } else {
            confirmInput.setCustomValidity('');
        }
    }

    showError(message) {
        if (this.errorDiv) {
            this.errorDiv.textContent = message;
            this.errorDiv.classList.remove('hidden');
        }
        if (this.successDiv) {
            this.successDiv.classList.add('hidden');
        }
    }

    showSuccess(message) {
        if (this.successDiv) {
            this.successDiv.textContent = message;
            this.successDiv.classList.remove('hidden');
        }
        if (this.errorDiv) {
            this.errorDiv.classList.add('hidden');
        }
    }

    clearMessages() {
        if (this.errorDiv) {
            this.errorDiv.classList.add('hidden');
        }
        if (this.successDiv) {
            this.successDiv.classList.add('hidden');
        }
    }

    async handleSubmit(event) {
        event.preventDefault();
        this.clearMessages();

        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        // Client-side validation
        if (!currentPassword || !newPassword || !confirmPassword) {
            this.showError('All fields are required');
            return;
        }

        if (newPassword.length < 6) {
            this.showError('New password must be at least 6 characters long');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showError('New passwords do not match');
            return;
        }

        if (currentPassword === newPassword) {
            this.showError('New password must be different from current password');
            return;
        }

        const token = localStorage.getItem('mcp_token');
        if (!token) {
            this.showError('You are not logged in');
            return;
        }

        try {
            const response = await fetch('/auth/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            });

            if (response.ok) {
                this.showSuccess('Password changed successfully');
                this.form.reset();
                
                // Auto-redirect after 2 seconds
                setTimeout(() => {
                    this.handleCancel();
                }, 2000);
            } else {
                const errorData = await response.text();
                this.showError(errorData || 'Failed to change password');
            }
        } catch (error) {
            console.error('Password change error:', error);
            this.showError('Network error. Please try again.');
        }
    }

    handleCancel() {
        // Determine where to go back based on the referrer or current context
        const referrer = document.referrer;
        
        if (referrer && referrer.includes('/ui/admin')) {
            window.location.href = '/ui/admin';
        } else if (referrer && referrer.includes('/ui/user')) {
            window.location.href = '/ui/user';
        } else {
            // Default fallback
            window.location.href = '/ui/user';
        }
    }
}

// Modal version for use within other pages
class PasswordChangeModal {
    constructor() {
        this.modal = null;
        this.form = null;
        this.errorDiv = null;
        this.successDiv = null;
        this.targetUsername = null; // For admin changing other user's password
    }

    createModal() {
        const modalHTML = `
            <div class="modal" id="changePasswordModal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Change Password</h3>
                        <button class="close-btn" onclick="passwordModal.close()">&times;</button>
                    </div>
                    <form id="modalChangePasswordForm">
                        <div id="modalPasswordError" class="error hidden"></div>
                        <div id="modalPasswordSuccess" class="success hidden"></div>
                        
                        <div class="form-group" id="currentPasswordGroup">
                            <label class="form-label">Current Password *</label>
                            <input type="password" class="form-input" id="modalCurrentPassword" required autocomplete="current-password">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">New Password *</label>
                            <input type="password" class="form-input" id="modalNewPassword" required autocomplete="new-password" minlength="6">
                            <div class="form-help">Password must be at least 6 characters long</div>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Confirm New Password *</label>
                            <input type="password" class="form-input" id="modalConfirmPassword" required autocomplete="new-password" minlength="6">
                        </div>
                        
                        <div class="actions">
                            <button type="submit" class="btn">Change Password</button>
                            <button type="button" class="btn btn-secondary" onclick="passwordModal.close()">Cancel</button>
                        </div>
                    </form>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
        this.modal = document.getElementById('changePasswordModal');
        this.form = document.getElementById('modalChangePasswordForm');
        this.errorDiv = document.getElementById('modalPasswordError');
        this.successDiv = document.getElementById('modalPasswordSuccess');

        this.setupEventListeners();
    }

    setupEventListeners() {
        if (this.form) {
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        }

        // Add real-time password confirmation validation
        const confirmPasswordInput = document.getElementById('modalConfirmPassword');
        const newPasswordInput = document.getElementById('modalNewPassword');
        
        if (confirmPasswordInput && newPasswordInput) {
            confirmPasswordInput.addEventListener('input', () => {
                this.validatePasswordMatch();
            });
            
            newPasswordInput.addEventListener('input', () => {
                this.validatePasswordMatch();
            });
        }

        // Close modal when clicking outside
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.close();
            }
        });
    }

    validatePasswordMatch() {
        const newPassword = document.getElementById('modalNewPassword').value;
        const confirmPassword = document.getElementById('modalConfirmPassword').value;
        const confirmInput = document.getElementById('modalConfirmPassword');
        
        if (confirmPassword && newPassword !== confirmPassword) {
            confirmInput.setCustomValidity('Passwords do not match');
        } else {
            confirmInput.setCustomValidity('');
        }
    }

    showError(message) {
        if (this.errorDiv) {
            this.errorDiv.textContent = message;
            this.errorDiv.classList.remove('hidden');
        }
        if (this.successDiv) {
            this.successDiv.classList.add('hidden');
        }
    }

    showSuccess(message) {
        if (this.successDiv) {
            this.successDiv.textContent = message;
            this.successDiv.classList.remove('hidden');
        }
        if (this.errorDiv) {
            this.errorDiv.classList.add('hidden');
        }
    }

    clearMessages() {
        if (this.errorDiv) {
            this.errorDiv.classList.add('hidden');
        }
        if (this.successDiv) {
            this.successDiv.classList.add('hidden');
        }
    }

    open() {
        if (!this.modal) {
            this.createModal();
        }

        this.clearMessages();
        this.form.reset();

        this.modal.style.display = 'block';
        document.getElementById('modalCurrentPassword').focus();
    }

    close() {
        if (this.modal) {
            this.modal.style.display = 'none';
        }
    }

    async handleSubmit(event) {
        event.preventDefault();
        this.clearMessages();

        const currentPassword = document.getElementById('modalCurrentPassword').value;
        const newPassword = document.getElementById('modalNewPassword').value;
        const confirmPassword = document.getElementById('modalConfirmPassword').value;

        // Client-side validation
        if (!currentPassword) {
            this.showError('Current password is required');
            return;
        }

        if (!newPassword || !confirmPassword) {
            this.showError('All password fields are required');
            return;
        }

        if (newPassword.length < 6) {
            this.showError('New password must be at least 6 characters long');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showError('New passwords do not match');
            return;
        }

        if (currentPassword === newPassword) {
            this.showError('New password must be different from current password');
            return;
        }

        const token = localStorage.getItem('mcp_token');
        if (!token) {
            this.showError('You are not logged in');
            return;
        }

        try {
            const response = await fetch('/auth/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            });

            if (response.ok) {
                this.showSuccess('Password changed successfully');
                
                // Auto-close after 1.5 seconds
                setTimeout(() => {
                    this.close();
                }, 1500);
            } else {
                const errorData = await response.text();
                this.showError(errorData || 'Failed to change password');
            }
        } catch (error) {
            console.error('Password change error:', error);
            this.showError('Network error. Please try again.');
        }
    }
}

// Global instance for modal usage
window.passwordModal = new PasswordChangeModal();

// Initialize the password changer when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const passwordChanger = new PasswordChanger();
    passwordChanger.initialize();
});

// Global function to open change password page
function openChangePasswordPage() {
    window.location.href = '/ui/change-password.html';
}
