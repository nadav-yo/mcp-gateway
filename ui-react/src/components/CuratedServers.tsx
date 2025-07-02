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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  SelectChangeEvent,
  Snackbar,
} from '@mui/material';
import {
  Storage,
  Add,
  Edit,
  Delete,
  ContentCopy,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface CuratedServer {
  id: number;
  name: string;
  type: string;
  url?: string;
  command?: string;
  args?: string[];
  description: string;
  created_at: string;
  updated_at: string;
}

interface ServerFormData {
  name: string;
  type: string;
  url: string;
  command: string;
  args: string[];
  description: string;
}

interface CuratedServersProps {
  adminMode?: boolean;
}

export const CuratedServers: React.FC<CuratedServersProps> = ({ adminMode = false }) => {
  const [servers, setServers] = useState<CuratedServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [editingServer, setEditingServer] = useState<CuratedServer | null>(null);
  const [formData, setFormData] = useState<ServerFormData>({
    name: '',
    type: 'stdio',
    url: '',
    command: '',
    args: [],
    description: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });
  const { token } = useAuth();

  useEffect(() => {
    fetchCuratedServers();
  }, []);

  const fetchCuratedServers = async () => {
    try {
      const endpoint = adminMode ? '/api/curated-servers' : '/gateway/curated-servers';
      const headers: HeadersInit = {};
      
      if (adminMode && token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch(endpoint, { headers });
      if (response.ok) {
        const data = await response.json();
        // Handle different response formats
        const serverList = adminMode ? data.data || [] : data.servers || [];
        setServers(serverList);
      } else {
        setError('Failed to load curated servers');
      }
    } catch (err) {
      setError('Network error loading curated servers');
      console.error('Error fetching curated servers:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenDialog = (server?: CuratedServer) => {
    if (server) {
      setEditingServer(server);
      setFormData({
        name: server.name,
        type: server.type,
        url: server.url || '',
        command: server.command || '',
        args: server.args || [],
        description: server.description || '',
      });
    } else {
      setEditingServer(null);
      setFormData({
        name: '',
        type: 'stdio',
        url: '',
        command: '',
        args: [],
        description: '',
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingServer(null);
    setFormData({
      name: '',
      type: 'stdio',
      url: '',
      command: '',
      args: [],
      description: '',
    });
  };

  const handleFormChange = (field: keyof ServerFormData, value: string | string[]) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleTypeChange = (event: SelectChangeEvent) => {
    const newType = event.target.value;
    setFormData(prev => ({
      ...prev,
      type: newType,
      // Clear type-specific fields when changing type
      url: newType === 'stdio' ? '' : prev.url,
      command: newType !== 'stdio' ? '' : prev.command,
    }));
  };

  const handleArgsChange = (value: string) => {
    const args = value.split('\n').filter(arg => arg.trim() !== '');
    setFormData(prev => ({ ...prev, args }));
  };

  const handleSubmit = async () => {
    if (!token) return;

    setSubmitting(true);
    try {
      const url = editingServer
        ? `/api/curated-servers/${editingServer.id}`
        : '/api/curated-servers';
      
      const method = editingServer ? 'PUT' : 'POST';
      
      const payload: any = {
        name: formData.name,
        type: formData.type,
        description: formData.description,
      };

      if (formData.type === 'stdio') {
        payload.command = formData.command;
        payload.args = formData.args;
      } else {
        payload.url = formData.url;
      }

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        await fetchCuratedServers();
        handleCloseDialog();
        setSnackbar({
          open: true,
          message: `Server ${editingServer ? 'updated' : 'created'} successfully`,
          severity: 'success',
        });
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to save server');
      }
    } catch (err) {
      console.error('Error saving server:', err);
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to save server',
        severity: 'error',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (serverId: number) => {
    if (!token || !window.confirm('Are you sure you want to delete this server?')) return;

    try {
      const response = await fetch(`/api/curated-servers/${serverId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        await fetchCuratedServers();
        setSnackbar({
          open: true,
          message: 'Server deleted successfully',
          severity: 'success',
        });
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to delete server');
      }
    } catch (err) {
      console.error('Error deleting server:', err);
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to delete server',
        severity: 'error',
      });
    }
  };

  const handleCopyConfig = (server: CuratedServer) => {
    const config = {
      name: server.name,
      type: server.type,
      ...(server.type === 'stdio' 
        ? { command: server.command, args: server.args }
        : { url: server.url }
      ),
    };
    
    navigator.clipboard.writeText(JSON.stringify(config, null, 2));
    setSnackbar({
      open: true,
      message: 'Configuration copied to clipboard',
      severity: 'success',
    });
  };

  const validateForm = () => {
    if (!formData.name || !formData.type) return false;
    
    if (formData.type === 'stdio') {
      return !!formData.command;
    } else {
      return !!formData.url;
    }
  };

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
              <Storage sx={{ mr: 1, color: 'primary.main' }} />
              <Typography variant="h6" component="h2">
                Curated MCP Servers
              </Typography>
            </Box>
            {adminMode && (
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={() => handleOpenDialog()}
              >
                Add Server
              </Button>
            )}
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {servers.length === 0 ? (
            <Box textAlign="center" py={3}>
              <Typography variant="body2" color="textSecondary">
                No curated servers available.
              </Typography>
            </Box>
          ) : (
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Configuration</TableCell>
                    <TableCell>Description</TableCell>
                    {adminMode && <TableCell align="center">Actions</TableCell>}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {servers.map((server) => (
                    <TableRow key={server.id}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {server.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={server.type.toUpperCase()}
                          size="small"
                          variant="outlined"
                          color={server.type === 'stdio' ? 'primary' : server.type === 'http' ? 'secondary' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ maxWidth: 300 }}>
                          {server.type === 'stdio' ? (
                            <Box>
                              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                {server.command}
                              </Typography>
                              {server.args && server.args.length > 0 && (
                                <Typography variant="caption" color="textSecondary">
                                  Args: {server.args.join(' ')}
                                </Typography>
                              )}
                            </Box>
                          ) : (
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                              {server.url}
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ maxWidth: 250 }}>
                          {server.description || 'No description'}
                        </Typography>
                      </TableCell>
                      {adminMode && (
                        <TableCell align="center">
                          <Box display="flex" gap={1} justifyContent="center">
                            <Tooltip title="Copy Configuration">
                              <IconButton
                                size="small"
                                onClick={() => handleCopyConfig(server)}
                              >
                                <ContentCopy />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Edit Server">
                              <IconButton
                                size="small"
                                onClick={() => handleOpenDialog(server)}
                              >
                                <Edit />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete Server">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleDelete(server.id)}
                              >
                                <Delete />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Add/Edit Server Dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingServer ? 'Edit Server' : 'Add New Server'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
            <TextField
              label="Server Name"
              value={formData.name}
              onChange={(e) => handleFormChange('name', e.target.value)}
              required
              fullWidth
            />

            <FormControl fullWidth required>
              <InputLabel>Server Type</InputLabel>
              <Select
                value={formData.type}
                onChange={handleTypeChange}
                label="Server Type"
              >
                <MenuItem value="stdio">Standard I/O</MenuItem>
                <MenuItem value="http">HTTP</MenuItem>
                <MenuItem value="ws">WebSocket</MenuItem>
              </Select>
            </FormControl>

            {formData.type === 'stdio' ? (
              <>
                <TextField
                  label="Command"
                  value={formData.command}
                  onChange={(e) => handleFormChange('command', e.target.value)}
                  required
                  fullWidth
                  placeholder="e.g., python, node, /path/to/executable"
                  helperText="The command to execute the MCP server"
                />
                <TextField
                  label="Arguments"
                  value={formData.args.join('\n')}
                  onChange={(e) => handleArgsChange(e.target.value)}
                  multiline
                  rows={3}
                  fullWidth
                  placeholder="Enter one argument per line"
                  helperText="Command-line arguments, one per line"
                />
              </>
            ) : (
              <TextField
                label="URL"
                value={formData.url}
                onChange={(e) => handleFormChange('url', e.target.value)}
                required
                fullWidth
                placeholder={`e.g., ${formData.type}://localhost:3000/mcp`}
                helperText={`The ${formData.type.toUpperCase()} endpoint URL`}
              />
            )}

            <TextField
              label="Description"
              value={formData.description}
              onChange={(e) => handleFormChange('description', e.target.value)}
              multiline
              rows={2}
              fullWidth
              placeholder="Describe what this server provides..."
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
            {submitting ? 'Saving...' : editingServer ? 'Update' : 'Create'}
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
