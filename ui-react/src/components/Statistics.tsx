import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Button,
  CircularProgress,
  Alert,
  Divider,
} from '@mui/material';
import {
  Assessment,
  Refresh,
  Security,
  Storage,
  Computer,
  VpnKey,
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
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon }) => (
  <Card sx={{ height: '100%', display: 'flex', alignItems: 'center' }}>
    <CardContent sx={{ width: '100%', textAlign: 'center' }}>
      {icon && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
          {icon}
        </Box>
      )}
      <Typography variant="h4" component="div" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
        {value}
      </Typography>
      <Typography variant="body2" color="textSecondary">
        {title}
      </Typography>
    </CardContent>
  </Card>
);

interface DistributionCardProps {
  title: string;
  data: Record<string, number>;
  icon?: React.ReactNode;
}

const DistributionCard: React.FC<DistributionCardProps> = ({ title, data, icon }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        {icon && <Box sx={{ mr: 1 }}>{icon}</Box>}
        <Typography variant="h6" component="h3">
          {title}
        </Typography>
      </Box>
      {Object.keys(data).length === 0 ? (
        <Typography variant="body2" color="textSecondary" textAlign="center">
          No data available
        </Typography>
      ) : (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {Object.entries(data).map(([key, value]) => (
            <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2">
                {formatLabel(key)}
              </Typography>
              <Typography variant="h6" color="primary.main">
                {value}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
    </CardContent>
  </Card>
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

  const fetchStatistics = async () => {
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
  };

  useEffect(() => {
    fetchStatistics();
  }, [token]);

  if (loading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="center" alignItems="center" minHeight={200}>
            <CircularProgress />
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent>
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
          <Box textAlign="center">
            <Button variant="contained" onClick={fetchStatistics} startIcon={<Refresh />}>
              Retry
            </Button>
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (!stats || !info) {
    return (
      <Card>
        <CardContent>
          <Typography variant="body2" color="textSecondary" textAlign="center">
            No statistics available
          </Typography>
        </CardContent>
      </Card>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Assessment sx={{ mr: 1, color: 'primary.main' }} />
              <Typography variant="h5" component="h1">
                Gateway Statistics
              </Typography>
            </Box>
            <Button variant="outlined" onClick={fetchStatistics} startIcon={<Refresh />}>
              Refresh
            </Button>
          </Box>
          {lastUpdated && (
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
              Last updated: {lastUpdated.toLocaleString()}
            </Typography>
          )}
        </CardContent>
      </Card>

      {/* Core Statistics */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Core Statistics
          </Typography>
          <Box sx={{ 
            display: 'flex', 
            flexWrap: 'wrap', 
            gap: 2,
            '& > *': { flex: '1 1 200px', minWidth: '200px' }
          }}>
            <StatCard 
              title="Total Servers" 
              value={stats.upstream_servers} 
              icon={<Storage color="primary" />}
            />
            <StatCard 
              title="Connected Servers" 
              value={stats.connected_servers}
              icon={<Computer color="success" />}
            />
            <StatCard 
              title="Available Tools" 
              value={stats.total_tools}
            />
            <StatCard 
              title="Available Prompts" 
              value={stats.total_prompts}
            />
            <StatCard 
              title="Available Resources" 
              value={stats.total_resources}
            />
            <StatCard 
              title="Requests Processed" 
              value={stats.requests_processed}
            />
          </Box>
        </CardContent>
      </Card>

      {/* User & Security Statistics */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            User & Security
          </Typography>
          <Box sx={{ 
            display: 'flex', 
            flexWrap: 'wrap', 
            gap: 2,
            '& > *': { flex: '1 1 200px', minWidth: '200px' }
          }}>
            <StatCard 
              title="Active Tokens" 
              value={stats.active_tokens}
              icon={<VpnKey color="primary" />}
            />
            <StatCard 
              title="Total Users" 
              value={stats.total_users}
              icon={<Security color="primary" />}
            />
            <StatCard 
              title="Blocked Tools" 
              value={stats.total_blocked_tools}
            />
            <StatCard 
              title="Blocked Prompts" 
              value={stats.total_blocked_prompts}
            />
            <StatCard 
              title="Blocked Resources" 
              value={stats.total_blocked_resources}
            />
          </Box>
        </CardContent>
      </Card>

      {/* Distribution Charts */}
      <Box sx={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        gap: 3,
        '& > *': { flex: '1 1 300px', minWidth: '300px' }
      }}>
        <DistributionCard 
          title="Server Status Distribution"
          data={stats.servers_by_status}
          icon={<Assessment color="primary" />}
        />
        <DistributionCard 
          title="Server Type Distribution"
          data={stats.servers_by_type}
          icon={<Storage color="primary" />}
        />
        <DistributionCard 
          title="Authentication Methods"
          data={stats.auth_methods_count}
          icon={<Security color="primary" />}
        />
      </Box>

      {/* Gateway Information */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Gateway Information
          </Typography>
          <Box sx={{ 
            display: 'flex', 
            flexWrap: 'wrap', 
            gap: 2,
            '& > *': { flex: '1 1 200px', minWidth: '200px' }
          }}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="textSecondary">
                Gateway Name
              </Typography>
              <Typography variant="h6">
                {info.name}
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="textSecondary">
                Gateway Version
              </Typography>
              <Typography variant="h6">
                {info.version}
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="textSecondary">
                System Uptime
              </Typography>
              <Typography variant="h6">
                {stats.system_uptime || '-'}
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="textSecondary">
                Last Database Update
              </Typography>
              <Typography variant="h6">
                {formatTimestamp(stats.last_database_update) || 'Never'}
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="textSecondary">
                Last Updated
              </Typography>
              <Typography variant="h6">
                {lastUpdated ? lastUpdated.toLocaleString() : '-'}
              </Typography>
            </Box>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};
