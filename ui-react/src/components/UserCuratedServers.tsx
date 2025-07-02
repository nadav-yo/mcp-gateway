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
  IconButton,
  Tooltip,
  Snackbar,
} from '@mui/material';
import {
  Storage,
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

export const UserCuratedServers: React.FC = () => {
  const [servers, setServers] = useState<CuratedServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });
  const { token } = useAuth();

  useEffect(() => {
    fetchCuratedServers();
  }, []);

  const fetchCuratedServers = async () => {
    try {
      setLoading(true);
      setError('');

      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch('/api/curated-servers', { headers });
      if (response.ok) {
        const data = await response.json();
        // Handle API response format { success: true, data: [...] }
        setServers(data.data || []);
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

  const generateMCPConfig = (server: CuratedServer): string => {
    let serverConfig: any = {};
    
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
  };

  const handleCopyConfig = (server: CuratedServer) => {
    const configText = generateMCPConfig(server);
    
    navigator.clipboard.writeText(configText).then(() => {
      setSnackbar({
        open: true,
        message: 'MCP configuration copied to clipboard',
        severity: 'success',
      });
    }).catch(err => {
      console.error('Failed to copy configuration:', err);
      setSnackbar({
        open: true,
        message: 'Failed to copy configuration to clipboard',
        severity: 'error',
      });
    });
  };

  const getTypeLabel = (type: string): string => {
    switch (type) {
      case 'stdio': return 'STDIO';
      case 'http': return 'HTTP';
      case 'ws': return 'WebSocket';
      default: return type.toUpperCase();
    }
  };

  const formatDate = (dateString: string): string => {
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return dateString;
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
                Curated Servers
              </Typography>
            </Box>
            <Typography variant="body2" color="textSecondary">
              {servers.length} curated servers
            </Typography>
          </Box>

          <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
            Browse pre-configured MCP servers that can be easily deployed. These are template servers that you can quickly set up without manual configuration.
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {servers.length === 0 ? (
            <Box textAlign="center" py={3}>
              <Typography variant="body2" color="textSecondary">
                No curated servers found.
              </Typography>
            </Box>
          ) : (
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Command/URL</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell align="center">Actions</TableCell>
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
                          label={getTypeLabel(server.type)}
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
                                  Args: {server.args.slice(0, 2).join(', ')}{server.args.length > 2 ? '...' : ''}
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
                          {server.description && server.description.length > 100 
                            ? server.description.substring(0, 100) + '...' 
                            : server.description || 'No description'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {formatDate(server.created_at)}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Tooltip title="Copy MCP config">
                          <IconButton
                            size="small"
                            onClick={() => handleCopyConfig(server)}
                          >
                            <ContentCopy />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

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
