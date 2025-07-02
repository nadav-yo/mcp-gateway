import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Button,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  CircularProgress,
  Chip,
} from '@mui/material';
import {
  VpnKey,
  Add,
  Delete,
  ContentCopy,
  CheckCircle,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface Token {
  id: number;
  description: string;
  token: string;
  created_at: string;
  last_used?: string;
  expires_at?: string;
}

export const TokenManagement: React.FC = () => {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newTokenName, setNewTokenName] = useState('');
  const [newToken, setNewToken] = useState('');
  const [creating, setCreating] = useState(false);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const { makeAuthenticatedRequest } = useAuth();

  const fetchTokens = useCallback(async () => {
    try {
      const response = await makeAuthenticatedRequest('/api/auth/tokens');
      if (response.ok) {
        const data = await response.json();
        console.log('Token data from API:', data); // Debug log
        setTokens(data || []);
      } else {
        setError('Failed to load tokens');
      }
    } catch (err: any) {
      setError(err.message || 'Network error loading tokens');
    } finally {
      setLoading(false);
    }
  }, [makeAuthenticatedRequest]);

  useEffect(() => {
    fetchTokens();
  }, [fetchTokens]);

  const handleCreateToken = async () => {
    if (!newTokenName.trim()) {
      return;
    }

    setCreating(true);
    try {
      const response = await makeAuthenticatedRequest('/api/auth/tokens', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          description: newTokenName.trim(),
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setNewToken(data.token);
        setNewTokenName('');
        await fetchTokens();
      } else {
        const errorText = await response.text();
        setError(errorText || 'Failed to create token');
      }
    } catch (err: any) {
      setError(err.message || 'Network error creating token');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteToken = async (tokenId: number) => {
    try {
      const response = await makeAuthenticatedRequest(`/api/auth/tokens/revoke?id=${tokenId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        await fetchTokens();
      } else {
        const errorText = await response.text();
        setError(errorText || 'Failed to delete token');
      }
    } catch (err: any) {
      setError(err.message || 'Network error deleting token');
    }
  };


  const handleCopyToken = async (token: string) => {
    try {
      await navigator.clipboard.writeText(token);
      setCopiedToken(token);
      setTimeout(() => setCopiedToken(null), 2000);
    } catch (err) {
      console.error('Failed to copy token:', err);
    }
  };

  const handleCloseCreateDialog = () => {
    setCreateDialogOpen(false);
    setNewTokenName('');
    setNewToken('');
    setError('');
  };

  const formatExpirationTime = (expiresAt?: string) => {
    if (!expiresAt) {
      return <Chip label="Never" size="small" color="default" />;
    }

    const expirationDate = new Date(expiresAt);
    const now = new Date();
    const timeDiff = expirationDate.getTime() - now.getTime();
    
    if (timeDiff <= 0) {
      return <Chip label="Expired" size="small" color="error" />;
    }

    const days = Math.floor(timeDiff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((timeDiff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));

    if (days > 0) {
      return <Typography variant="body2">{days} day{days !== 1 ? 's' : ''}</Typography>;
    } else if (hours > 0) {
      return <Typography variant="body2">{hours} hour{hours !== 1 ? 's' : ''}</Typography>;
    } else if (minutes > 0) {
      return <Typography variant="body2">{minutes} minute{minutes !== 1 ? 's' : ''}</Typography>;
    } else {
      return <Typography variant="body2" color="error">Less than 1 minute</Typography>;
    }
  };

  const formatRelativeTime = (dateString?: string) => {
    if (!dateString) {
      return <Chip label="Never" size="small" />;
    }

    const date = new Date(dateString);
    const now = new Date();
    const timeDiff = now.getTime() - date.getTime();
    
    if (timeDiff < 0) {
      return <Typography variant="body2" color="error">Invalid date</Typography>;
    }

    const days = Math.floor(timeDiff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((timeDiff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));

    if (days > 0) {
      return <Typography variant="body2">{days} day{days !== 1 ? 's' : ''} ago</Typography>;
    } else if (hours > 0) {
      return <Typography variant="body2">{hours} hour{hours !== 1 ? 's' : ''} ago</Typography>;
    } else if (minutes > 0) {
      return <Typography variant="body2">{minutes} minute{minutes !== 1 ? 's' : ''} ago</Typography>;
    } else {
      return <Typography variant="body2">Just now</Typography>;
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
    <Card>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Box display="flex" alignItems="center">
            <VpnKey sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" component="h2">
              API Tokens
            </Typography>
          </Box>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Create Token
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {tokens.length === 0 ? (
          <Box textAlign="center" py={3}>
            <Typography variant="body2" color="textSecondary">
              No API tokens found. Create one to get started.
            </Typography>
          </Box>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Token</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Last Used</TableCell>
                  <TableCell>Expires In</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {tokens.map((token) => (
                  <TableRow key={token.id}>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {token.description || 'No description'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontFamily="monospace"
                      >
                        {token.token.substring(0, 8)}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {token.created_at ? new Date(token.created_at).toLocaleDateString() : 'Invalid Date'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {formatRelativeTime(token.last_used)}
                    </TableCell>
                    <TableCell>
                      {formatExpirationTime(token.expires_at)}
                    </TableCell>
                    <TableCell align="right">
                      <IconButton
                        color="error"
                        onClick={() => handleDeleteToken(token.id)}
                      >
                        <Delete />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Create Token Dialog */}
        <Dialog
          open={createDialogOpen}
          onClose={handleCloseCreateDialog}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle>Create New API Token</DialogTitle>
          <DialogContent>
            {newToken ? (
              <Box>
                <Alert severity="success" sx={{ mb: 2 }}>
                  Token created successfully! Make sure to copy it now - you won't be able to see it again.
                </Alert>
                <Box
                  sx={{
                    p: 2,
                    pr: 6, // Add right padding to make room for the copy button
                    bgcolor: 'background.paper',
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1,
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                    position: 'relative',
                    color: 'text.primary',
                  }}
                >
                  {newToken}
                  <IconButton
                    sx={{ position: 'absolute', top: 4, right: 4 }}
                    onClick={() => handleCopyToken(newToken)}
                  >
                    {copiedToken === newToken ? (
                      <CheckCircle color="success" />
                    ) : (
                      <ContentCopy />
                    )}
                  </IconButton>
                </Box>
              </Box>
            ) : (
              <TextField
                autoFocus
                margin="dense"
                label="Token Name"
                fullWidth
                variant="outlined"
                value={newTokenName}
                onChange={(e) => setNewTokenName(e.target.value)}
                disabled={creating}
                helperText="Give your token a descriptive name"
              />
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseCreateDialog}>
              {newToken ? 'Done' : 'Cancel'}
            </Button>
            {!newToken && (
              <Button
                onClick={handleCreateToken}
                variant="contained"
                disabled={!newTokenName.trim() || creating}
              >
                {creating ? 'Creating...' : 'Create Token'}
              </Button>
            )}
          </DialogActions>
        </Dialog>
      </CardContent>
    </Card>
  );
};
