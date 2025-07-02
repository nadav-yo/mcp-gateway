import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Divider,
  FormControlLabel,
  Checkbox,
  Switch,
  Alert,
  CircularProgress,
  IconButton,
  Chip,
  Paper,
} from '@mui/material';
import {
  Description,
  Refresh,
  Download,
  GetApp,
  Computer,
  Storage,
  Security,
  Schedule,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface ServerLog {
  filename: string;
  server_id: number;
  server_name: string;
  size: number;
  modified: string;
}

interface LogsListResponse {
  success: boolean;
  data: {
    logs: ServerLog[];
    count: number;
  };
  message?: string;
  error?: string;
}

interface LogContentResponse {
  success: boolean;
  data: {
    content: string;
    path?: string;
    size?: number;
  };
  message?: string;
  error?: string;
}

const GATEWAY_LOGS = [
  {
    filename: 'request.log',
    name: 'Request Log',
    description: 'All HTTP requests with trace IDs and user information'
  },
  {
    filename: 'audit.log',
    name: 'Audit Log',
    description: 'Administrative actions: user creation/updates/deletion and server management'
  }
];

interface LogsProps {
  selectedServerId?: number;
  selectedServerName?: string;
}

export const Logs: React.FC<LogsProps> = ({ selectedServerId, selectedServerName }) => {
  const [serverLogs, setServerLogs] = useState<ServerLog[]>([]);
  const [currentLogType, setCurrentLogType] = useState<'gateway' | 'server' | null>(null);
  const [currentLogServerId, setCurrentLogServerId] = useState<number | null>(null);
  const [currentLogFilename, setCurrentLogFilename] = useState<string | null>(null);
  const [currentServerName, setCurrentServerName] = useState<string>('');
  const [logContent, setLogContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [logsListLoading, setLogsListLoading] = useState(true);
  const [error, setError] = useState('');
  const [tailEnabled, setTailEnabled] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  
  const autoRefreshTimerRef = useRef<NodeJS.Timeout | null>(null);
  const logContentRef = useRef<HTMLDivElement>(null);
  
  const { token } = useAuth();

  // Format file size utility
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Load available server logs
  const loadServerLogs = async () => {
    setLogsListLoading(true);
    try {
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch('/api/logs', { headers });
      const result: LogsListResponse = await response.json();

      if (result.success) {
        setServerLogs(result.data.logs);
      } else {
        throw new Error(result.message || result.error || 'Failed to load logs');
      }
    } catch (error) {
      console.error('Error loading logs:', error);
      setError(error instanceof Error ? error.message : 'Failed to load logs');
    } finally {
      setLogsListLoading(false);
    }
  };

  // Load gateway log content
  const loadGatewayLog = async (filename: string) => {
    setLoading(true);
    setError('');
    setCurrentLogType('gateway');
    setCurrentLogServerId(null);
    setCurrentLogFilename(filename);

    try {
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      let url = `/api/logs/${filename}`;
      if (tailEnabled) {
        url += '?tail=true&lines=100';
      }

      const response = await fetch(url, { headers });
      const result: LogContentResponse = await response.json();

      if (result.success) {
        setLogContent(result.data.content || '');
        setLastUpdated(new Date());
        
        // Auto-scroll to bottom
        setTimeout(() => {
          if (logContentRef.current) {
            logContentRef.current.scrollTop = logContentRef.current.scrollHeight;
          }
        }, 100);
      } else {
        throw new Error(result.message || result.error || 'Failed to load log');
      }
    } catch (error) {
      console.error('Error loading gateway log:', error);
      setError(error instanceof Error ? error.message : 'Failed to load log');
    } finally {
      setLoading(false);
    }
  };

  // Load server log content
  const loadServerLog = async (serverId: number, serverName: string) => {
    setLoading(true);
    setError('');
    setCurrentLogType('server');
    setCurrentLogServerId(serverId);
    setCurrentLogFilename(null);
    setCurrentServerName(serverName);

    try {
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      let url = `/api/upstream-servers/${serverId}/logs`;
      if (tailEnabled) {
        url += '?tail=true&lines=100';
      }

      const response = await fetch(url, { headers });
      const result: LogContentResponse = await response.json();

      if (result.success) {
        setLogContent(result.data.content || '');
        setLastUpdated(new Date());
        
        // Auto-scroll to bottom
        setTimeout(() => {
          if (logContentRef.current) {
            logContentRef.current.scrollTop = logContentRef.current.scrollHeight;
          }
        }, 100);
      } else {
        throw new Error(result.message || result.error || 'Failed to load log');
      }
    } catch (error) {
      console.error('Error loading server log:', error);
      setError(error instanceof Error ? error.message : 'Failed to load log');
    } finally {
      setLoading(false);
    }
  };

  // Refresh current log
  const refreshCurrentLog = () => {
    if (currentLogType === 'gateway' && currentLogFilename) {
      loadGatewayLog(currentLogFilename);
    } else if (currentLogType === 'server' && currentLogServerId) {
      loadServerLog(currentLogServerId, currentServerName);
    }
  };

  // Download current log
  const downloadCurrentLog = async () => {
    try {
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      let url = '';
      let filename = '';

      if (currentLogType === 'gateway' && currentLogFilename) {
        url = `/api/logs/${currentLogFilename}?download=true`;
        filename = currentLogFilename;
      } else if (currentLogType === 'server' && currentLogServerId) {
        url = `/api/upstream-servers/${currentLogServerId}/logs?download=true`;
        filename = `server-${currentLogServerId}.log`;
      } else {
        return;
      }

      const response = await fetch(url, { headers });
      
      if (response.ok) {
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(downloadUrl);
      } else {
        throw new Error('Failed to download log file');
      }
    } catch (error) {
      console.error('Error downloading log:', error);
      setError(error instanceof Error ? error.message : 'Failed to download log');
    }
  };

  // Toggle tail mode
  const handleTailToggle = (event: React.ChangeEvent<HTMLInputElement>) => {
    setTailEnabled(event.target.checked);
    // Refresh current log with new tail setting
    if (currentLogType) {
      setTimeout(refreshCurrentLog, 100);
    }
  };

  // Toggle auto-refresh
  const handleAutoRefreshToggle = (event: React.ChangeEvent<HTMLInputElement>) => {
    setAutoRefresh(event.target.checked);
  };

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh && currentLogType) {
      autoRefreshTimerRef.current = setInterval(() => {
        refreshCurrentLog();
      }, 5000); // Refresh every 5 seconds

      return () => {
        if (autoRefreshTimerRef.current) {
          clearInterval(autoRefreshTimerRef.current);
        }
      };
    } else {
      if (autoRefreshTimerRef.current) {
        clearInterval(autoRefreshTimerRef.current);
        autoRefreshTimerRef.current = null;
      }
    }
  }, [autoRefresh, currentLogType, currentLogFilename, currentLogServerId, tailEnabled]);

  // Load server logs on component mount
  useEffect(() => {
    loadServerLogs();
  }, [token]);

  // Handle automatic server selection when props are provided
  useEffect(() => {
    if (selectedServerId && selectedServerName && serverLogs.length > 0) {
      // Find the server in the logs list and auto-select it
      const serverLog = serverLogs.find(log => log.server_id === selectedServerId);
      if (serverLog) {
        loadServerLog(selectedServerId, selectedServerName);
      }
    }
  }, [selectedServerId, selectedServerName, serverLogs]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (autoRefreshTimerRef.current) {
        clearInterval(autoRefreshTimerRef.current);
      }
    };
  }, []);

  const getCurrentLogTitle = (): string => {
    if (currentLogType === 'gateway' && currentLogFilename) {
      return `Gateway Log: ${currentLogFilename}`;
    } else if (currentLogType === 'server' && currentServerName) {
      return `Logs for ${currentServerName}`;
    }
    return 'Select a log to view';
  };

  const hasCurrentLog = currentLogType !== null;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Description sx={{ mr: 1, color: 'primary.main' }} />
              <Typography variant="h5" component="h1">
                Gateway Logs
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={autoRefresh}
                    onChange={handleAutoRefreshToggle}
                    size="small"
                  />
                }
                label="Auto-refresh"
              />
              <Button
                variant="outlined"
                onClick={loadServerLogs}
                startIcon={<Refresh />}
                disabled={logsListLoading}
              >
                Refresh Logs List
              </Button>
            </Box>
          </Box>
          <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
            View logs for the gateway and individual servers. Request logs capture all HTTP requests, while server logs capture individual server events.
          </Typography>
          {lastUpdated && (
            <Typography variant="body2" color="textSecondary">
              Last updated: {lastUpdated.toLocaleString()}
            </Typography>
          )}
        </CardContent>
      </Card>

      <Box sx={{ display: 'flex', gap: 3, height: '70vh', minHeight: '600px' }}>
        {/* Logs List */}
        <Card sx={{ width: '300px', display: 'flex', flexDirection: 'column' }}>
          <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <Typography variant="h6" gutterBottom>
              Available Logs
            </Typography>

            {/* Gateway Logs */}
            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
              Gateway Logs
            </Typography>
            <List dense sx={{ mb: 2 }}>
              {GATEWAY_LOGS.map((gatewayLog) => (
                <ListItem key={gatewayLog.filename} disablePadding>
                  <ListItemButton
                    selected={currentLogType === 'gateway' && currentLogFilename === gatewayLog.filename}
                    onClick={() => loadGatewayLog(gatewayLog.filename)}
                  >
                    <ListItemText
                      primary={gatewayLog.name}
                      secondary={gatewayLog.description}
                    />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>

            <Divider />

            {/* Server Logs */}
            <Typography variant="subtitle2" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
              Available Server Logs
            </Typography>
            
            {logsListLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                <CircularProgress size={24} />
              </Box>
            ) : error ? (
              <Alert severity="error" sx={{ mt: 1 }}>
                Error loading logs: {error}
              </Alert>
            ) : serverLogs.length === 0 ? (
              <Typography variant="body2" color="textSecondary" sx={{ textAlign: 'center', py: 2 }}>
                No server log files found
              </Typography>
            ) : (
              <List dense sx={{ flex: 1, overflow: 'auto' }}>
                {serverLogs.map((log) => (
                  <ListItem key={`${log.server_id}-${log.filename}`} disablePadding>
                    <ListItemButton
                      selected={currentLogType === 'server' && currentLogServerId === log.server_id}
                      onClick={() => loadServerLog(log.server_id, log.server_name)}
                    >
                      <ListItemText
                        primary={log.server_name}
                        secondary={
                          <Box>
                            <Typography variant="body2" color="textSecondary">
                              ID: {log.server_id} | Size: {formatFileSize(log.size)}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              Modified: {new Date(log.modified).toLocaleString()}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItemButton>
                  </ListItem>
                ))}
              </List>
            )}
          </CardContent>
        </Card>

        {/* Log Viewer */}
        <Card sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {/* Log Viewer Header */}
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">
                {getCurrentLogTitle()}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={tailEnabled}
                      onChange={handleTailToggle}
                      size="small"
                    />
                  }
                  label="Tail (last 100 lines)"
                />
                <Button
                  variant="outlined"
                  size="small"
                  onClick={refreshCurrentLog}
                  disabled={!hasCurrentLog || loading}
                  startIcon={<Refresh />}
                >
                  Refresh
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={downloadCurrentLog}
                  disabled={!hasCurrentLog}
                  startIcon={<Download />}
                >
                  Download
                </Button>
              </Box>
            </Box>

            {/* Log Content */}
            <Paper
              ref={logContentRef}
              sx={{
                flex: 1,
                p: 2,
                bgcolor: 'grey.50',
                fontFamily: 'monospace',
                fontSize: '12px',
                overflow: 'auto',
                overflowY: 'scroll',
                overflowX: 'auto',
                whiteSpace: 'pre',
                wordBreak: 'normal',
                border: '1px solid',
                borderColor: 'divider',
              }}
            >
              {loading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <CircularProgress />
                </Box>
              ) : error ? (
                <Alert severity="error">
                  {error}
                </Alert>
              ) : !hasCurrentLog ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <Typography variant="body2" color="textSecondary">
                    Select a log from the list to view its contents
                  </Typography>
                </Box>
              ) : logContent.trim() === '' ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <Typography variant="body2" color="textSecondary">
                    Log file is empty
                  </Typography>
                </Box>
              ) : (
                logContent
              )}
            </Paper>
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
};
