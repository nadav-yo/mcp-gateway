import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  CircularProgress,
  Alert,
  Button,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControlLabel,
  Checkbox,
  Snackbar,
} from '@mui/material';
import {
  People,
  Add,
  Delete,
  Refresh,
  AdminPanelSettings,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface User {
  id: number;
  username: string;
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
  updated_at: string;
}

interface UserFormData {
  username: string;
  password: string;
  is_admin: boolean;
}

export const UserManagement: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [formData, setFormData] = useState<UserFormData>({
    username: '',
    password: '',
    is_admin: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });
  const { token, user: currentUser } = useAuth();

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    if (!token) return;

    try {
      const response = await fetch('/admin/users', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const userData = await response.json();
        setUsers(userData);
      } else {
        setError('Failed to load users');
      }
    } catch (err) {
      setError('Network error loading users');
      console.error('Error fetching users:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenDialog = () => {
    setFormData({
      username: '',
      password: '',
      is_admin: false,
    });
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setFormData({
      username: '',
      password: '',
      is_admin: false,
    });
  };

  const handleFormChange = (field: keyof UserFormData, value: string | boolean) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async () => {
    if (!token) return;

    setSubmitting(true);
    try {
      const response = await fetch('/admin/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        await fetchUsers();
        handleCloseDialog();
        setSnackbar({
          open: true,
          message: `User "${formData.username}" created successfully`,
          severity: 'success',
        });
      } else {
        const errorData = await response.text();
        throw new Error(errorData || 'Failed to create user');
      }
    } catch (err) {
      console.error('Error creating user:', err);
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to create user',
        severity: 'error',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (userId: number, username: string) => {
    if (!token || !window.confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
      return;
    }

    try {
      const response = await fetch(`/admin/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        await fetchUsers();
        setSnackbar({
          open: true,
          message: `User "${username}" deleted successfully`,
          severity: 'success',
        });
      } else {
        const errorData = await response.text();
        throw new Error(errorData || 'Failed to delete user');
      }
    } catch (err) {
      console.error('Error deleting user:', err);
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to delete user',
        severity: 'error',
      });
    }
  };

  const validateForm = () => {
    return formData.username.trim() !== '' && formData.password.trim() !== '' && formData.password.length >= 6;
  };

  const isCurrentUser = (user: User) => {
    return currentUser && currentUser.id === user.id;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  const activeUsers = users.filter(user => user.is_active).length;

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="center" alignItems="center" minHeight={120}>
            <CircularProgress />
          </Box>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
            <Box display="flex" alignItems="center">
              <People sx={{ mr: 1, color: 'primary.main' }} />
              <Typography variant="h6" component="h2">
                User Management
              </Typography>
            </Box>
            <Box display="flex" gap={1}>
              <Button
                variant="outlined"
                startIcon={<Refresh />}
                onClick={fetchUsers}
              >
                Reload
              </Button>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleOpenDialog}
              >
                Add User
              </Button>
            </Box>
          </Box>

          <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
            Create and manage user accounts for the MCP Gateway. Admin users have full access to manage servers, view logs, and manage other users.
          </Typography>

          <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
            {users.length} users ({activeUsers} active)
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {users.length === 0 ? (
            <Box textAlign="center" py={3}>
              <Typography variant="body2" color="textSecondary">
                No users found.
              </Typography>
            </Box>
          ) : (
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Username</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>Updated</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="body2" fontWeight="medium">
                            {user.username}
                          </Typography>
                          {user.is_admin && (
                            <Chip
                              icon={<AdminPanelSettings />}
                              label="Admin"
                              size="small"
                              color="primary"
                            />
                          )}
                          {isCurrentUser(user) && (
                            <Chip
                              label="You"
                              size="small"
                              variant="outlined"
                              color="secondary"
                            />
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={user.is_active ? 'Active' : 'Inactive'}
                          size="small"
                          color={user.is_active ? 'success' : 'error'}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {formatDate(user.created_at)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {formatDate(user.updated_at)}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Box display="flex" gap={1} justifyContent="center">
                          {!isCurrentUser(user) && users.length > 1 && (
                            <Tooltip title="Delete User">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleDelete(user.id, user.username)}
                              >
                                <Delete />
                              </IconButton>
                            </Tooltip>
                          )}
                          {isCurrentUser(user) && (
                            <Typography variant="caption" color="textSecondary">
                              Current User
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Add User Dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle>Add New User</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
            <TextField
              label="Username"
              value={formData.username}
              onChange={(e) => handleFormChange('username', e.target.value)}
              required
              fullWidth
              autoFocus
            />

            <TextField
              label="Password"
              type="password"
              value={formData.password}
              onChange={(e) => handleFormChange('password', e.target.value)}
              required
              fullWidth
              helperText="Password must be at least 6 characters long"
            />

            <FormControlLabel
              control={
                <Checkbox
                  checked={formData.is_admin}
                  onChange={(e) => handleFormChange('is_admin', e.target.checked)}
                />
              }
              label="Admin User"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button
            onClick={handleSubmit}
            variant="contained"
            disabled={!validateForm() || submitting}
          >
            {submitting ? 'Creating...' : 'Create User'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
      >
        <Alert
          onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </>
  );
};
