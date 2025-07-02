import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  CircularProgress,
  Alert,
  Button,
  IconButton,
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
  Switch,
  FormControlLabel,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Collapse,
} from '@mui/material';
import {
  Storage,
  Add,
  Edit,
  Delete,
  PowerSettingsNew,
  Refresh,
  Search,
  Clear,
  Description,
  AccessTime,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface UpstreamServer {
  id: number;
  name: string;
  type: string;
  url?: string;
  command?: string[];
  enabled: boolean;
  status: string;
  description?: string;
  prefix?: string;
  auth_type?: string;
  auth_username?: string;
  auth_header_name?: string;
  created_at: string;
  updated_at: string;
  last_seen?: string;
  tool_details?: Tool[];
  prompt_details?: Prompt[];
  resource_details?: Resource[];
  runtime_connected?: boolean;
}

interface Tool {
  name: string;
  description?: string;
  blocked?: boolean;
  serverId?: number;
  serverType?: string;
}

interface Prompt {
  name: string;
  description?: string;
  blocked?: boolean;
  serverId?: number;
  serverType?: string;
}

interface Resource {
  name: string;
  description?: string;
  uri?: string;
  blocked?: boolean;
  serverId?: number;
  serverType?: string;
}

interface ServerFormData {
  name: string;
  type: string;
  url: string;
  command: string;
  enabled: boolean;
  prefix: string;
  description: string;
}

interface UpstreamServersProps {
  adminMode?: boolean;
  onTabChange?: (tabIndex: number, serverId?: number, serverName?: string) => void;
}

export const UpstreamServers: React.FC<UpstreamServersProps> = ({ adminMode = false, onTabChange }) => {
  const [servers, setServers] = useState<UpstreamServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [editingServer, setEditingServer] = useState<UpstreamServer | null>(null);
  const [formData, setFormData] = useState<ServerFormData>({
    name: '',
    type: 'stdio',
    url: '',
    command: '',
    enabled: true,
    prefix: '',
    description: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' | 'info' });
  const [searchTerm, setSearchTerm] = useState('');
  const [connectedOnly, setConnectedOnly] = useState(false);

  const [expandedTools, setExpandedTools] = useState<Set<number>>(new Set());
  const [expandedResources, setExpandedResources] = useState<Set<number>>(new Set());
  const [expandedPrompts, setExpandedPrompts] = useState<Set<number>>(new Set());
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshTimer, setRefreshTimer] = useState<NodeJS.Timeout | null>(null);
  const { token } = useAuth();

  const fetchUpstreamServers = useCallback(async (isAutoRefresh = false) => {
    try {
      // Only set loading state on initial load, not during auto-refresh
      if (!isAutoRefresh) {
        setLoading(true);
      }
      setError('');

      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      // Fetch both servers and status information
      const [serversResponse, statusResponse] = await Promise.all([
        fetch('/api/upstream-servers', { headers }),
        fetch('/gateway/status', { headers }),
      ]);

      if (serversResponse.ok && statusResponse.ok) {
        const serversData = await serversResponse.json();
        const statusData = await statusResponse.json();
        
        if (serversData.success) {
          // Merge server data with runtime status
          const mergedServers = mergeServersWithStatus(serversData.data.servers || [], statusData);
          setServers(mergedServers);
          setLastUpdated(new Date());
        } else {
          setError('Failed to load upstream servers');
        }
      } else {
        setError('Failed to load upstream servers');
      }
    } catch (err) {
      setError('Network error loading upstream servers');
      console.error('Error fetching upstream servers:', err);
    } finally {
      // Only clear loading state if we set it
      if (!isAutoRefresh) {
        setLoading(false);
      }
    }
  }, [token]);

  useEffect(() => {
    fetchUpstreamServers();
  }, [fetchUpstreamServers]);

  useEffect(() => {
    if (autoRefresh) {
      const timer = setInterval(() => {
        fetchUpstreamServers(true); // Pass true to indicate this is an auto-refresh
      }, 5000); // Refresh every 5 seconds
      setRefreshTimer(timer);
      return () => clearInterval(timer);
    } else if (refreshTimer) {
      clearInterval(refreshTimer);
      setRefreshTimer(null);
    }
  }, [autoRefresh, fetchUpstreamServers, refreshTimer]);

  useEffect(() => {
    return () => {
      if (refreshTimer) {
        clearInterval(refreshTimer);
      }
    };
  }, [refreshTimer]);

  const mergeServersWithStatus = (serverList: UpstreamServer[], statusData: any): UpstreamServer[] => {
    const upstreamServers = statusData.gateway?.upstream_servers || [];
    
    const statusMap: Record<string, any> = {};
    upstreamServers.forEach((upstream: any) => {
      statusMap[upstream.name] = {
        tool_details: upstream.tool_details || [],
        prompt_details: upstream.prompt_details || [],
        resource_details: upstream.resource_details || [],
        connected: upstream.connected,
      };
    });

    return serverList.map(server => ({
      ...server,
      tool_details: statusMap[server.name]?.tool_details || [],
      prompt_details: statusMap[server.name]?.prompt_details || [],
      resource_details: statusMap[server.name]?.resource_details || [],
      runtime_connected: statusMap[server.name]?.connected || false,
    }));
  };

  const handleOpenDialog = (server?: UpstreamServer) => {
    if (server) {
      setEditingServer(server);
      setFormData({
        name: server.name,
        type: server.type,
        url: server.url || '',
        command: server.command?.join(' ') || '',
        enabled: server.enabled,
        prefix: server.prefix || '',
        description: server.description || '',
      });
    } else {
      setEditingServer(null);
      setFormData({
        name: '',
        type: 'stdio',
        url: '',
        command: '',
        enabled: true,
        prefix: '',
        description: '',
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingServer(null);
  };

  const handleFormChange = (field: keyof ServerFormData, value: string | boolean) => {
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

  const handleSubmit = async () => {
    if (!token || !adminMode) return;

    setSubmitting(true);
    try {
      const url = editingServer
        ? `/api/upstream-servers/${editingServer.id}`
        : '/api/upstream-servers';
      
      const method = editingServer ? 'PUT' : 'POST';
      
      const payload: any = {
        name: formData.name,
        type: formData.type,
        enabled: formData.enabled,
        prefix: formData.prefix,
        description: formData.description,
      };

      if (formData.type === 'stdio') {
        payload.command = formData.command.split(' ').filter(cmd => cmd.trim() !== '');
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
        await fetchUpstreamServers(true); // Preserve expanded state after server save
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

  const handleToggleServer = async (serverId: number) => {
    if (!token || !adminMode) return;

    try {
      const response = await fetch(`/api/upstream-servers/${serverId}/toggle`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        await fetchUpstreamServers(true); // Preserve expanded state after server toggle
        setSnackbar({
          open: true,
          message: 'Server status updated successfully',
          severity: 'success',
        });
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to toggle server');
      }
    } catch (err) {
      console.error('Error toggling server:', err);
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to toggle server',
        severity: 'error',
      });
    }
  };

  const handleDelete = async (serverId: number) => {
    if (!token || !adminMode || !window.confirm('Are you sure you want to delete this server?')) return;

    try {
      const response = await fetch(`/api/upstream-servers/${serverId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        await fetchUpstreamServers();
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



  const toggleToolsExpansion = (serverId: number) => {
    setExpandedTools(prev => {
      const newSet = new Set(prev);
      if (newSet.has(serverId)) {
        newSet.delete(serverId);
      } else {
        // Close other sections and open tools
        setExpandedResources(prevRes => {
          const newResSet = new Set(prevRes);
          newResSet.delete(serverId);
          return newResSet;
        });
        setExpandedPrompts(prevProm => {
          const newPromSet = new Set(prevProm);
          newPromSet.delete(serverId);
          return newPromSet;
        });
        newSet.add(serverId);
      }
      return newSet;
    });
  };

  const toggleResourcesExpansion = (serverId: number) => {
    setExpandedResources(prev => {
      const newSet = new Set(prev);
      if (newSet.has(serverId)) {
        newSet.delete(serverId);
      } else {
        // Close other sections and open resources
        setExpandedTools(prevTools => {
          const newToolsSet = new Set(prevTools);
          newToolsSet.delete(serverId);
          return newToolsSet;
        });
        setExpandedPrompts(prevProm => {
          const newPromSet = new Set(prevProm);
          newPromSet.delete(serverId);
          return newPromSet;
        });
        newSet.add(serverId);
      }
      return newSet;
    });
  };

  const togglePromptsExpansion = (serverId: number) => {
    setExpandedPrompts(prev => {
      const newSet = new Set(prev);
      if (newSet.has(serverId)) {
        newSet.delete(serverId);
      } else {
        // Close other sections and open prompts
        setExpandedTools(prevTools => {
          const newToolsSet = new Set(prevTools);
          newToolsSet.delete(serverId);
          return newToolsSet;
        });
        setExpandedResources(prevRes => {
          const newResSet = new Set(prevRes);
          newResSet.delete(serverId);
          return newResSet;
        });
        newSet.add(serverId);
      }
      return newSet;
    });
  };

  const handleViewLogs = (serverId: number, serverName: string) => {
    // Call parent component to switch to the Logs tab (index 4)
    if (onTabChange) {
      onTabChange(4, serverId, serverName);
    } else {
      // Fallback: show message if no tab change callback is provided
      setSnackbar({
        open: true,
        message: `Opening logs for ${serverName} (Server ID: ${serverId})`,
        severity: 'info',
      });
    }
  };

  const handleToggleAutoRefresh = () => {
    setAutoRefresh(!autoRefresh);
  };

  const handleManualRefresh = () => {
    fetchUpstreamServers(true); // Pass true to preserve expanded state during manual refresh
  };

  const getStatusColor = (server: UpstreamServer): 'success' | 'warning' | 'error' | 'default' => {
    if (!server.enabled) return 'default';
    if (server.runtime_connected || server.status === 'connected') return 'success';
    if (server.status === 'starting') return 'warning';
    return 'error';
  };

  const getStatusLabel = (server: UpstreamServer): string => {
    if (!server.enabled) return 'Disabled';
    if (server.runtime_connected || server.status === 'connected') return 'Connected';
    if (server.status === 'starting') return 'Starting';
    if (server.status === 'error') return 'Error';
    return 'Disconnected';
  };



  const validateForm = () => {
    if (!formData.name || !formData.type) return false;
    
    if (formData.type === 'stdio') {
      return !!formData.command;
    } else {
      return !!formData.url;
    }
  };

  const handleToggleToolBlock = async (serverId: number, toolName: string, isEnabled: boolean) => {
    if (!token || !adminMode) return;

    try {
      const response = await fetch('/api/blocked-tools/toggle', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          server_id: serverId,
          type: 'servers',
          tool_name: toolName,
          block: !isEnabled, // if enabled=true, we want to unblock (block=false)
        }),
      });

      if (response.ok) {
        // Update the local state to reflect the change
        setServers(prevServers => 
          prevServers.map(server => 
            server.id === serverId 
              ? {
                  ...server,
                  tool_details: server.tool_details?.map(tool => 
                    tool.name === toolName 
                      ? { ...tool, blocked: !isEnabled }
                      : tool
                  )
                }
              : server
          )
        );
        
        setSnackbar({
          open: true,
          message: `Tool ${isEnabled ? 'enabled' : 'blocked'} successfully`,
          severity: 'success',
        });
      } else {
        throw new Error('Failed to toggle tool');
      }
    } catch (err) {
      console.error('Error toggling tool block:', err);
      setSnackbar({
        open: true,
        message: `Failed to ${isEnabled ? 'enable' : 'block'} tool`,
        severity: 'error',
      });
    }
  };

  const handleToggleResourceBlock = async (serverId: number, resourceName: string, isEnabled: boolean) => {
    if (!token || !adminMode) return;

    try {
      const response = await fetch('/api/blocked-resources/toggle', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          server_id: serverId,
          type: 'servers',
          resource_name: resourceName,
          block: !isEnabled, // if enabled=true, we want to unblock (block=false)
        }),
      });

      if (response.ok) {
        // Update the local state to reflect the change
        setServers(prevServers => 
          prevServers.map(server => 
            server.id === serverId 
              ? {
                  ...server,
                  resource_details: server.resource_details?.map(resource => 
                    resource.name === resourceName 
                      ? { ...resource, blocked: !isEnabled }
                      : resource
                  )
                }
              : server
          )
        );
        
        setSnackbar({
          open: true,
          message: `Resource ${isEnabled ? 'enabled' : 'blocked'} successfully`,
          severity: 'success',
        });
      } else {
        throw new Error('Failed to toggle resource');
      }
    } catch (err) {
      console.error('Error toggling resource block:', err);
      setSnackbar({
        open: true,
        message: `Failed to ${isEnabled ? 'enable' : 'block'} resource`,
        severity: 'error',
      });
    }
  };

  const handleTogglePromptBlock = async (serverId: number, promptName: string, isEnabled: boolean) => {
    if (!token || !adminMode) return;

    try {
      const response = await fetch('/api/blocked-prompts/toggle', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          server_id: serverId,
          type: 'servers',
          prompt_name: promptName,
          block: !isEnabled, // if enabled=true, we want to unblock (block=false)
        }),
      });

      if (response.ok) {
        // Update the local state to reflect the change
        setServers(prevServers => 
          prevServers.map(server => 
            server.id === serverId 
              ? {
                  ...server,
                  prompt_details: server.prompt_details?.map(prompt => 
                    prompt.name === promptName 
                      ? { ...prompt, blocked: !isEnabled }
                      : prompt
                  )
                }
              : server
          )
        );
        
        setSnackbar({
          open: true,
          message: `Prompt ${isEnabled ? 'enabled' : 'blocked'} successfully`,
          severity: 'success',
        });
      } else {
        throw new Error('Failed to toggle prompt');
      }
    } catch (err) {
      console.error('Error toggling prompt block:', err);
      setSnackbar({
        open: true,
        message: `Failed to ${isEnabled ? 'enable' : 'block'} prompt`,
        severity: 'error',
      });
    }
  };

  const filteredServers = servers.filter(server => {
    const matchesSearch = !searchTerm || 
      server.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (server.description && server.description.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesFilter = !connectedOnly || 
      (server.enabled && (server.runtime_connected || server.status === 'connected'));
    
    return matchesSearch && matchesFilter;
  });

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
                Upstream Servers
              </Typography>
            </Box>
            <Box display="flex" alignItems="center" gap={1}>
              <Typography variant="body2" color="textSecondary">
                {filteredServers.length}/{servers.length} servers
              </Typography>
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
          </Box>

          {/* Search and Filter Controls */}
          <Box display="flex" alignItems="center" gap={2} mb={2}>
            <Box display="flex" alignItems="center" gap={1} flex={1}>
              <Search sx={{ color: 'action.active' }} />
              <TextField
                size="small"
                placeholder="Search servers..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                sx={{ flex: 1 }}
                InputProps={{
                  endAdornment: searchTerm && (
                    <IconButton size="small" onClick={() => setSearchTerm('')}>
                      <Clear />
                    </IconButton>
                  ),
                }}
              />
            </Box>
            <Button
              variant={connectedOnly ? 'contained' : 'outlined'}
              size="small"
              onClick={() => setConnectedOnly(!connectedOnly)}
            >
              Connected Only
            </Button>
            <FormControlLabel
              control={
                <Switch
                  checked={autoRefresh}
                  onChange={handleToggleAutoRefresh}
                  size="small"
                />
              }
              label="Auto-refresh"
            />
            <IconButton onClick={handleManualRefresh} title="Refresh Now">
              <Refresh />
            </IconButton>
          </Box>

          {/* Last Updated Info */}
          {lastUpdated && (
            <Box display="flex" alignItems="center" gap={1} mb={2}>
              <AccessTime sx={{ fontSize: 16, color: 'text.secondary' }} />
              <Typography variant="caption" color="textSecondary">
                Last updated: {lastUpdated.toLocaleTimeString()}
              </Typography>
            </Box>
          )}

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {filteredServers.length === 0 ? (
            <Box textAlign="center" py={3}>
              <Typography variant="body2" color="textSecondary">
                No servers found
              </Typography>
            </Box>
          ) : (
            filteredServers.map((server) => (
              <Card key={server.id} sx={{ mb: 2 }}>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                    <Box flex={1}>
                      <Box display="flex" alignItems="center" gap={1} mb={1}>
                        <Typography variant="h6" component="h3">
                          {server.name}
                        </Typography>
                        <Chip
                          label={getStatusLabel(server)}
                          color={getStatusColor(server)}
                          size="small"
                        />
                        <Chip 
                          label={server.type.toUpperCase()} 
                          size="small" 
                          variant="outlined"
                          color={server.type === 'stdio' ? 'primary' : server.type === 'http' ? 'secondary' : 'default'}
                        />
                        <Chip 
                          label={`${server.tool_details?.length || 0} Tools`}
                          size="small" 
                          variant={expandedTools.has(server.id) ? "filled" : "outlined"}
                          color={expandedTools.has(server.id) ? "primary" : "default"}
                          onClick={() => toggleToolsExpansion(server.id)}
                          sx={{ cursor: 'pointer' }}
                        />
                        <Chip 
                          label={`${server.resource_details?.length || 0} Resources`}
                          size="small" 
                          variant={expandedResources.has(server.id) ? "filled" : "outlined"}
                          color={expandedResources.has(server.id) ? "secondary" : "default"}
                          onClick={() => toggleResourcesExpansion(server.id)}
                          sx={{ cursor: 'pointer' }}
                        />
                        <Chip 
                          label={`${server.prompt_details?.length || 0} Prompts`}
                          size="small" 
                          variant={expandedPrompts.has(server.id) ? "filled" : "outlined"}
                          color={expandedPrompts.has(server.id) ? "success" : "default"}
                          onClick={() => togglePromptsExpansion(server.id)}
                          sx={{ cursor: 'pointer' }}
                        />
                      </Box>
                      
                      {/* Command/URL line */}
                      <Typography 
                        variant="body2" 
                        color="primary.main" 
                        sx={{ 
                          fontFamily: 'monospace', 
                          fontSize: '0.875rem', 
                          mb: 0.5,
                          fontWeight: 500,
                          backgroundColor: 'primary.50',
                          px: 1,
                          py: 0.5,
                          borderRadius: 1,
                          display: 'inline-block'
                        }}
                      >
                        {server.type === 'stdio' && server.command && server.command.length > 0
                          ? server.command.join(' ')
                          : server.url || 'N/A'}
                      </Typography>
                      
                      {/* Description line */}
                      {server.description && (
                        <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                          {server.description}
                        </Typography>
                      )}
                    </Box>

                    {adminMode && (
                      <Box display="flex" gap={1}>
                        <IconButton
                          size="small"
                          onClick={() => handleOpenDialog(server)}
                          title="Edit Server"
                        >
                          <Edit />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleToggleServer(server.id)}
                          title={server.enabled ? 'Disable Server' : 'Enable Server'}
                        >
                          <PowerSettingsNew color={server.enabled ? 'error' : 'success'} />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleViewLogs(server.id, server.name)}
                          title="View Logs"
                        >
                          <Description />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleDelete(server.id)}
                          title="Delete Server"
                          color="error"
                        >
                          <Delete />
                        </IconButton>
                      </Box>
                    )}
                  </Box>

                  {/* Tools Section */}
                  <Collapse in={expandedTools.has(server.id)}>
                    <Box mt={2}>
                      <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 600, color: 'primary.main' }}>
                        Tools ({server.tool_details?.length || 0})
                      </Typography>
                      <TableContainer component={Paper} variant="outlined">
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Name</TableCell>
                              <TableCell>Description</TableCell>
                              {adminMode && <TableCell align="center">Status</TableCell>}
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {server.tool_details && server.tool_details.length > 0 ? (
                              [...server.tool_details].sort((a, b) => a.name.localeCompare(b.name)).map((tool, index) => (
                                <TableRow key={index}>
                                  <TableCell>{tool.name}</TableCell>
                                  <TableCell>{tool.description || 'No description'}</TableCell>
                                  {adminMode && (
                                    <TableCell align="center">
                                      <FormControlLabel
                                        control={
                                          <Switch
                                            checked={!tool.blocked}
                                            onChange={(e) => handleToggleToolBlock(server.id, tool.name, e.target.checked)}
                                            size="small"
                                          />
                                        }
                                        label={tool.blocked ? 'Blocked' : 'Enabled'}
                                        labelPlacement="end"
                                        sx={{ margin: 0 }}
                                      />
                                    </TableCell>
                                  )}
                                </TableRow>
                              ))
                            ) : (
                              <TableRow>
                                <TableCell colSpan={adminMode ? 3 : 2}>
                                  <Typography variant="body2" color="textSecondary" align="center">
                                    No tools available
                                  </Typography>
                                </TableCell>
                              </TableRow>
                            )}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  </Collapse>

                  {/* Resources Section */}
                  <Collapse in={expandedResources.has(server.id)}>
                    <Box mt={2}>
                      <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 600, color: 'secondary.main' }}>
                        Resources ({server.resource_details?.length || 0})
                      </Typography>
                      <TableContainer component={Paper} variant="outlined">
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Name</TableCell>
                              <TableCell>URI</TableCell>
                              <TableCell>Description</TableCell>
                              {adminMode && <TableCell align="center">Status</TableCell>}
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {server.resource_details && server.resource_details.length > 0 ? (
                              [...server.resource_details].sort((a, b) => a.name.localeCompare(b.name)).map((resource, index) => (
                                <TableRow key={index}>
                                  <TableCell>{resource.name}</TableCell>
                                  <TableCell>{resource.uri || 'N/A'}</TableCell>
                                  <TableCell>{resource.description || 'No description'}</TableCell>
                                  {adminMode && (
                                    <TableCell align="center">
                                      <FormControlLabel
                                        control={
                                          <Switch
                                            checked={!resource.blocked}
                                            onChange={(e) => handleToggleResourceBlock(server.id, resource.name, e.target.checked)}
                                            size="small"
                                          />
                                        }
                                        label={resource.blocked ? 'Blocked' : 'Enabled'}
                                        labelPlacement="end"
                                        sx={{ margin: 0 }}
                                      />
                                    </TableCell>
                                  )}
                                </TableRow>
                              ))
                            ) : (
                              <TableRow>
                                <TableCell colSpan={adminMode ? 4 : 3}>
                                  <Typography variant="body2" color="textSecondary" align="center">
                                    No resources available
                                  </Typography>
                                </TableCell>
                              </TableRow>
                            )}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  </Collapse>

                  {/* Prompts Section */}
                  <Collapse in={expandedPrompts.has(server.id)}>
                    <Box mt={2}>
                      <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 600, color: 'success.main' }}>
                        Prompts ({server.prompt_details?.length || 0})
                      </Typography>
                      <TableContainer component={Paper} variant="outlined">
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Name</TableCell>
                              <TableCell>Description</TableCell>
                              {adminMode && <TableCell align="center">Status</TableCell>}
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {server.prompt_details && server.prompt_details.length > 0 ? (
                              [...server.prompt_details].sort((a, b) => a.name.localeCompare(b.name)).map((prompt, index) => (
                                <TableRow key={index}>
                                  <TableCell>{prompt.name}</TableCell>
                                  <TableCell>{prompt.description || 'No description'}</TableCell>
                                  {adminMode && (
                                    <TableCell align="center">
                                      <FormControlLabel
                                        control={
                                          <Switch
                                            checked={!prompt.blocked}
                                            onChange={(e) => handleTogglePromptBlock(server.id, prompt.name, e.target.checked)}
                                            size="small"
                                          />
                                        }
                                        label={prompt.blocked ? 'Blocked' : 'Enabled'}
                                        labelPlacement="end"
                                        sx={{ margin: 0 }}
                                      />
                                    </TableCell>
                                  )}
                                </TableRow>
                              ))
                            ) : (
                              <TableRow>
                                <TableCell colSpan={adminMode ? 3 : 2}>
                                  <Typography variant="body2" color="textSecondary" align="center">
                                    No prompts available
                                  </Typography>
                                </TableCell>
                              </TableRow>
                            )}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  </Collapse>
                </CardContent>
              </Card>
            ))
          )}
        </CardContent>
      </Card>

      {/* Add/Edit Server Dialog */}
      {adminMode && (
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
                  <MenuItem value="websocket">WebSocket</MenuItem>
                </Select>
              </FormControl>

              {formData.type === 'stdio' ? (
                <TextField
                  label="Command"
                  value={formData.command}
                  onChange={(e) => handleFormChange('command', e.target.value)}
                  required
                  fullWidth
                  placeholder="e.g., python server.py --port 8080"
                  helperText="The full command to execute the MCP server"
                />
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
                label="Prefix"
                value={formData.prefix}
                onChange={(e) => handleFormChange('prefix', e.target.value)}
                fullWidth
                placeholder="e.g., myserver"
                helperText="Optional prefix for tools/resources from this server"
              />

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
      )}

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

export default UpstreamServers;
