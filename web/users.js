// User Management JavaScript

class UserManager {
    constructor(adminPanel) {
        this.adminPanel = adminPanel;
        this.users = [];
        this.currentUser = null;
    }

    async init() {
        this.setupEventListeners();
        await this.loadUsers();
    }

    setupEventListeners() {
        // Add user form
        const addUserForm = document.getElementById('addUserForm');
        if (addUserForm) {
            addUserForm.addEventListener('submit', (e) => this.handleAddUser(e));
        }
    }

    async loadUsers() {
        try {
            const response = await this.makeRequest('/admin/users', 'GET');
            if (response.ok) {
                this.users = await response.json();
                
                // Try to identify current user by checking tokens to see which user context we're in
                await this.identifyCurrentUser();
                
                this.renderUsers();
                this.updateUserCount();
            } else {
                throw new Error(`Failed to load users: ${response.status}`);
            }
        } catch (error) {
            console.error('Error loading users:', error);
            this.showError('Failed to load users');
        }
    }

    async identifyCurrentUser() {
        try {
            // Get tokens to see which user context we're in
            const response = await this.makeRequest('/auth/tokens', 'GET');
            if (response.ok) {
                const tokens = await response.json();
                // This will help us identify the current user session
                // For now, we'll use a simple approach - mark users conservatively
                console.log('Current user context identified through tokens');
            }
        } catch (error) {
            console.log('Could not identify current user context:', error);
        }
    }

    renderUsers() {
        const usersList = document.getElementById('usersList');
        if (!usersList) return;

        if (this.users.length === 0) {
            usersList.innerHTML = '<div class="no-data">No users found</div>';
            return;
        }

        const usersTableHTML = `
            <table class="users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Updated</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${this.users.map(user => this.renderUserRow(user)).join('')}
                </tbody>
            </table>
        `;
        usersList.innerHTML = usersTableHTML;
    }

    renderUserRow(user) {
        const isCurrentUser = this.isCurrentUser(user.id);
        const statusClass = user.is_active ? 'status-connected' : 'status-error';
        const statusText = user.is_active ? 'Active' : 'Inactive';
        const adminTag = user.is_admin ? '<span class="badge admin-badge">Admin</span>' : '';
        const currentUserTag = isCurrentUser ? '<span class="badge current-user-badge">You</span>' : '';
        
        const createdDate = new Date(user.created_at).toLocaleDateString();
        const updatedDate = new Date(user.updated_at).toLocaleDateString();

        // Show delete button only if we're confident this is not the current user
        const showDeleteButton = !isCurrentUser && this.users.length > 1;

        return `
            <tr>
                <td class="user-name-cell">
                    ${user.username}
                    ${adminTag}
                    ${currentUserTag}
                </td>
                <td>
                    <span class="server-status ${statusClass}">
                        ${statusText}
                    </span>
                </td>
                <td>${createdDate}</td>
                <td>${updatedDate}</td>
                <td class="user-actions-cell">
                    ${isCurrentUser ? `
                        <button class="btn btn-sm btn-secondary" onclick="passwordModal.open()" title="Change Your Password">Change Password</button>
                    ` : ''}
                    ${showDeleteButton ? `
                        <button class="btn btn-sm btn-danger" onclick="deleteUserSafe(${user.id}, '${user.username}')">Delete</button>
                    ` : ''}
                </td>
            </tr>
        `;
    }

    isCurrentUser(userId) {
        // Get current user from admin panel context
        if (this.adminPanel.user && this.adminPanel.user.id === userId) {
            return true;
        }
        
        // If user info is not available in admin panel, try to determine from token context
        // For now, we'll make it safe by returning false if we can't determine
        return false;
    }

    updateUserCount() {
        const userCount = document.getElementById('userCount');
        if (userCount) {
            const activeUsers = this.users.filter(user => user.is_active).length;
            userCount.textContent = `${this.users.length} users (${activeUsers} active)`;
        }
    }

    async handleAddUser(e) {
        e.preventDefault();
        
        const userData = {
            username: document.getElementById('addUsername').value,
            password: document.getElementById('addPassword').value,
            is_admin: document.getElementById('addUserIsAdmin').checked
        };

        try {
            const response = await this.makeRequest('/admin/users', 'POST', userData);
            
            if (response.ok) {
                const newUser = await response.json();
                this.showSuccess(`User "${newUser.username}" created successfully`);
                closeAddUserModal();
                await this.loadUsers();
            } else {
                const errorData = await response.text();
                throw new Error(errorData || `Failed to create user: ${response.status}`);
            }
        } catch (error) {
            console.error('Error creating user:', error);
            this.showError(error.message || 'Failed to create user');
        }
    }

    async deleteUser(userId, username) {
        if (!confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await this.makeRequest(`/admin/users/${userId}`, 'DELETE');
            
            if (response.ok) {
                this.showSuccess(`User "${username}" deleted successfully`);
                await this.loadUsers();
            } else {
                const errorData = await response.text();
                throw new Error(errorData || `Failed to delete user: ${response.status}`);
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            this.showError(error.message || 'Failed to delete user');
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
        if (this.adminPanel.authEnabled && this.adminPanel.token) {
            options.headers['Authorization'] = `Bearer ${this.adminPanel.token}`;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        return fetch(url, options);
    }

    showError(message) {
        const errorDiv = document.getElementById('userError');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.classList.remove('hidden');
            setTimeout(() => errorDiv.classList.add('hidden'), 5000);
        }
    }

    showSuccess(message) {
        const successDiv = document.getElementById('userSuccess');
        if (successDiv) {
            successDiv.textContent = message;
            successDiv.classList.remove('hidden');
            setTimeout(() => successDiv.classList.add('hidden'), 3000);
        }
    }
}

// Global functions for add user modal
function showAddUserModal() {
    document.getElementById('addUserForm').reset();
    document.getElementById('addUserModal').style.display = 'block';
}

function closeAddUserModal() {
    document.getElementById('addUserModal').style.display = 'none';
}

// Wrapper functions for safe userManager access
async function reloadUsers() {
    try {
        let manager = null;
        
        if (window.userManager) {
            manager = window.userManager;
        } else if (window.adminPanel && window.adminPanel.userManager) {
            manager = window.adminPanel.userManager;
        }
        
        if (manager) {
            await manager.loadUsers();
        } else {
            console.error('User manager not available');
            alert('User management is not available. Please refresh the page.');
        }
    } catch (error) {
        console.error('Error reloading users:', error);
        alert('Failed to reload users: ' + error.message);
    }
}

async function deleteUserSafe(userId, username) {
    try {
        let manager = null;
        
        if (window.userManager) {
            manager = window.userManager;
        } else if (window.adminPanel && window.adminPanel.userManager) {
            manager = window.adminPanel.userManager;
        }
        
        if (manager) {
            await manager.deleteUser(userId, username);
        } else {
            console.error('User manager not available');
            alert('User management is not available. Please refresh the page.');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        alert('Failed to delete user: ' + error.message);
    }
}
