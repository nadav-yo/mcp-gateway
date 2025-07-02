import React, { useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Button,
  AppBar,
  Toolbar,
  Tabs,
  Tab,
  Paper,
} from '@mui/material';
import {
  Logout,
  Dashboard,
  People,
  Settings,
  Storage,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { UserInfo } from './UserInfo';
import { TokenManagement } from './TokenManagement';
import { CuratedServers } from './CuratedServers';

interface AdminPageProps {
  onLogout: () => void;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`admin-tabpanel-${index}`}
      aria-labelledby={`admin-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

export const AdminPage: React.FC<AdminPageProps> = ({ onLogout }) => {
  const [tabValue, setTabValue] = useState(0);
  const { logout } = useAuth();

  const handleLogout = async () => {
    await logout();
    onLogout();
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            MCP Gateway - Admin Dashboard
          </Typography>
          <Button
            color="inherit"
            startIcon={<Logout />}
            onClick={handleLogout}
          >
            Logout
          </Button>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Paper sx={{ width: '100%' }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              aria-label="admin tabs"
            >
              <Tab
                icon={<Dashboard />}
                label="Dashboard"
                id="admin-tab-0"
                aria-controls="admin-tabpanel-0"
              />
              <Tab
                icon={<People />}
                label="Users"
                id="admin-tab-1"
                aria-controls="admin-tabpanel-1"
              />
              <Tab
                icon={<Storage />}
                label="Curated Servers"
                id="admin-tab-2"
                aria-controls="admin-tabpanel-2"
              />
              <Tab
                icon={<Settings />}
                label="Settings"
                id="admin-tab-3"
                aria-controls="admin-tabpanel-3"
              />
            </Tabs>
          </Box>

          {/* Dashboard Tab */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {/* User Information */}
              <Box>
                <UserInfo />
              </Box>
              {/* Token Management */}
              <Box>
                <TokenManagement />
              </Box>
            </Box>
          </TabPanel>

          {/* Users Tab */}
          <TabPanel value={tabValue} index={1}>
            <Typography variant="h6" gutterBottom>
              User Management
            </Typography>
            <Typography variant="body2" color="textSecondary">
              User management functionality will be implemented here.
            </Typography>
          </TabPanel>

          {/* Servers Tab */}
          <TabPanel value={tabValue} index={2}>
            <CuratedServers adminMode={true} />
          </TabPanel>

          {/* Settings Tab */}
          <TabPanel value={tabValue} index={3}>
            <Typography variant="h6" gutterBottom>
              System Settings
            </Typography>
            <Typography variant="body2" color="textSecondary">
              System configuration and settings will be implemented here.
            </Typography>
          </TabPanel>
        </Paper>
      </Container>
    </Box>
  );
};
