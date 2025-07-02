import React, { useState, useEffect, useCallback } from 'react';
import {
  Typography,
  Box,
  Button,
  CircularProgress,
  Alert,
  Paper,
} from '@mui/material';
import {
  Assessment,
  Refresh,
  Security,
  Storage,
  Computer,
  VpnKey,
  Block,
  Timeline,
  Build,
  Folder,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

interface GatewayStats {
  upstream_servers: number;
  connected_servers: number;
  total_tools: number;
  total_prompts: number;
  total_resources: number;
  requests_processed: number;
  active_tokens: number;
  total_users: number;
  total_blocked_tools: number;
  total_blocked_prompts: number;
  total_blocked_resources: number;
  servers_by_status: Record<string, number>;
  servers_by_type: Record<string, number>;
  auth_methods_count: Record<string, number>;
  system_uptime: string;
  last_database_update: string;
}

interface GatewayInfo {
  name: string;
  version: string;
  description: string;
}

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: React.ReactNode;
  color?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color = 'primary.main' }) => (
  <Paper 
    elevation={2} 
    sx={{ 
      height: '100%',
      p: 2,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      textAlign: 'center',
      transition: 'all 0.2s ease-in-out',
      '&:hover': {
        elevation: 4,
        transform: 'translateY(-2px)',
      }
    }}
  >
    {icon && (
      <Box sx={{ mb: 1, color }}>
        {icon}
      </Box>
    )}
    <Typography variant="h4" component="div" sx={{ fontWeight: 'bold', color, mb: 0.5 }}>
      {value}
    </Typography>
    <Typography variant="body2" color="textSecondary" sx={{ fontSize: '0.875rem' }}>
      {title}
    </Typography>
  </Paper>
);

interface DistributionCardProps {
  title: string;
  data: Record<string, number>;
  icon?: React.ReactNode;
}

const DistributionCard: React.FC<DistributionCardProps> = ({ title, data, icon }) => (
  <Paper elevation={2} sx={{ height: '100%', p: 2 }}>
    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
      {icon && <Box sx={{ mr: 1, color: 'primary.main' }}>{icon}</Box>}
      <Typography variant="h6" component="h3" sx={{ fontWeight: 600 }}>
        {title}
      </Typography>
    </Box>
    {Object.keys(data).length === 0 ? (
      <Typography variant="body2" color="textSecondary" textAlign="center" sx={{ py: 2 }}>
        No data available
      </Typography>
    ) : (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
        {Object.entries(data).map(([key, value]) => (
          <Box key={key} sx={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            p: 1,
            borderRadius: 1,
            bgcolor: 'background.default'
          }}>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {formatLabel(key)}
            </Typography>
            <Typography variant="h6" color="primary.main" sx={{ fontWeight: 'bold' }}>
              {value}
            </Typography>
          </Box>
        ))}
      </Box>
    )}
  </Paper>
);

const formatLabel = (key: string): string => {
  return key.split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

const formatTimestamp = (timestamp: string): string => {
  if (!timestamp || timestamp === 'Never') {
    return 'Never';
  }
  
  try {
    const date = new Date(timestamp);
    if (isNaN(date.getTime())) {
      return timestamp;
    }
    return date.toLocaleString();
  } catch (error) {
    return timestamp;
  }
};

export const Statistics: React.FC = () => {
  const [stats, setStats] = useState<GatewayStats | null>(null);
  const [info, setInfo] = useState<GatewayInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const { token } = useAuth();

  const fetchStatistics = useCallback(async () => {
    setLoading(true);
    setError('');
    
    try {
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const [statsResponse, infoResponse] = await Promise.all([
        fetch('/gateway/stats', { headers }),
        fetch('/info', { headers }),
      ]);

      if (!statsResponse.ok) {
        throw new Error(`Failed to fetch statistics: ${statsResponse.statusText}`);
      }
      if (!infoResponse.ok) {
        throw new Error(`Failed to fetch info: ${infoResponse.statusText}`);
      }

      const statsData = await statsResponse.json();
      const infoData = await infoResponse.json();

      setStats(statsData);
      setInfo(infoData);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Error fetching statistics:', err);
      setError(err instanceof Error ? err.message : 'Failed to load statistics');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchStatistics();
  }, [token, fetchStatistics]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight={400}>
        <CircularProgress size={60} />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ maxWidth: 600, mx: 'auto', mt: 4 }}>
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
        <Box textAlign="center">
          <Button variant="contained" onClick={fetchStatistics} startIcon={<Refresh />}>
            Retry
          </Button>
        </Box>
      </Box>
    );
  }

  if (!stats || !info) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight={400}>
        <Typography variant="body1" color="textSecondary">
          No statistics available
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      <Paper elevation={1} sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Assessment sx={{ mr: 2, color: 'primary.main', fontSize: 32 }} />
            <Box>
              <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                Gateway Statistics
              </Typography>
              {lastUpdated && (
                <Typography variant="body2" color="textSecondary">
                  Last updated: {lastUpdated.toLocaleString()}
                </Typography>
              )}
            </Box>
          </Box>
          <Button 
            variant="contained" 
            onClick={fetchStatistics} 
            startIcon={<Refresh />}
            sx={{ minWidth: 120 }}
          >
            Refresh
          </Button>
        </Box>
      </Paper>

      {/* Core Statistics */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 600 }}>
        Core Statistics
      </Typography>
      <Box sx={{ 
        display: 'grid', 
        gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)', lg: 'repeat(6, 1fr)' },
        gap: 2,
        mb: 4
      }}>
        <StatCard 
          title="Total Servers" 
          value={stats.upstream_servers} 
          icon={<Storage sx={{ fontSize: 28 }} />}
          color="primary.main"
        />
        <StatCard 
          title="Connected Servers" 
          value={stats.connected_servers}
          icon={<Computer sx={{ fontSize: 28 }} />}
          color="success.main"
        />
        <StatCard 
          title="Available Tools" 
          value={stats.total_tools}
          icon={<Build sx={{ fontSize: 28 }} />}
          color="info.main"
        />
        <StatCard 
          title="Available Prompts" 
          value={stats.total_prompts}
          icon={<Assessment sx={{ fontSize: 28 }} />}
          color="warning.main"
        />
        <StatCard 
          title="Available Resources" 
          value={stats.total_resources}
          icon={<Folder sx={{ fontSize: 28 }} />}
          color="secondary.main"
        />
        <StatCard 
          title="Requests Processed" 
          value={stats.requests_processed}
          icon={<Timeline sx={{ fontSize: 28 }} />}
          color="success.main"
        />
      </Box>

      {/* User & Security Statistics */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 600 }}>
        User & Security
      </Typography>
      <Box sx={{ 
        display: 'grid', 
        gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)', lg: 'repeat(5, 1fr)' },
        gap: 2,
        mb: 4
      }}>
        <StatCard 
          title="Active Tokens" 
          value={stats.active_tokens}
          icon={<VpnKey sx={{ fontSize: 28 }} />}
          color="primary.main"
        />
        <StatCard 
          title="Total Users" 
          value={stats.total_users}
          icon={<Security sx={{ fontSize: 28 }} />}
          color="success.main"
        />
        <StatCard 
          title="Blocked Tools" 
          value={stats.total_blocked_tools}
          icon={<Block sx={{ fontSize: 28 }} />}
          color="error.main"
        />
        <StatCard 
          title="Blocked Prompts" 
          value={stats.total_blocked_prompts}
          icon={<Block sx={{ fontSize: 28 }} />}
          color="error.main"
        />
        <StatCard 
          title="Blocked Resources" 
          value={stats.total_blocked_resources}
          icon={<Block sx={{ fontSize: 28 }} />}
          color="error.main"
        />
      </Box>

      {/* Distribution Charts */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 600 }}>
        Distribution Analysis
      </Typography>
      <Box sx={{ 
        display: 'grid', 
        gridTemplateColumns: { xs: '1fr', md: 'repeat(3, 1fr)' },
        gap: 3,
        mb: 4
      }}>
        <DistributionCard 
          title="Server Status Distribution"
          data={stats.servers_by_status}
          icon={<Assessment />}
        />
        <DistributionCard 
          title="Server Type Distribution"
          data={stats.servers_by_type}
          icon={<Storage />}
        />
        <DistributionCard 
          title="Authentication Methods"
          data={stats.auth_methods_count}
          icon={<Security />}
        />
      </Box>

      {/* Gateway Information */}
      <Typography variant="h5" sx={{ mb: 2, fontWeight: 600 }}>
        Gateway Information
      </Typography>
      <Paper elevation={2} sx={{ p: 3 }}>
        <Box sx={{ 
          display: 'grid', 
          gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' },
          gap: 3
        }}>
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
              Gateway Name
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
              {info.name}
            </Typography>
          </Box>
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
              Gateway Version
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
              {info.version}
            </Typography>
          </Box>
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
              System Uptime
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
              {stats.system_uptime || '-'}
            </Typography>
          </Box>
          <Box sx={{ textAlign: 'center' }}>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
              Last Database Update
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
              {formatTimestamp(stats.last_database_update) || 'Never'}
            </Typography>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
};
