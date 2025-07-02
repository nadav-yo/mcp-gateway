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
  Storage,
  Assessment,
  Description,
  Router,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { UserInfo } from './UserInfo';
import { TokenManagement } from './TokenManagement';
import { CuratedServers } from './CuratedServers';
import { UserManagement } from './UserManagement';
import { Statistics } from './Statistics';
import { Logs } from './Logs';
import { UpstreamServers } from './UpstreamServers';
import { DarkModeToggle } from './DarkModeToggle';

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
  const [selectedLogServerId, setSelectedLogServerId] = useState<number | undefined>(undefined);
  const [selectedLogServerName, setSelectedLogServerName] = useState<string | undefined>(undefined);
  const { logout } = useAuth();

  const handleLogout = async () => {
    await logout();
    onLogout();
  };

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    // Clear selected server information when manually switching tabs
    setSelectedLogServerId(undefined);
    setSelectedLogServerName(undefined);
    setTabValue(newValue);
  };

  const handleTabChangeFromUpstreamServers = (tabIndex: number, serverId?: number, serverName?: string) => {
    // Set the selected server information for the Logs component
    setSelectedLogServerId(serverId);
    setSelectedLogServerName(serverName);
    // Switch to the specified tab
    setTabValue(tabIndex);
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            MCP Gateway - Admin Dashboard
          </Typography>
          <DarkModeToggle />
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
                icon={<Router />}
                label="Upstream Servers"
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
                icon={<Assessment />}
                label="Statistics"
                id="admin-tab-3"
                aria-controls="admin-tabpanel-3"
              />
              <Tab
                icon={<Description />}
                label="Logs"
                id="admin-tab-4"
                aria-controls="admin-tabpanel-4"
              />
              <Tab
                icon={<People />}
                label="Users"
                id="admin-tab-5"
                aria-controls="admin-tabpanel-5"
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

          {/* Upstream Servers Tab */}
          <TabPanel value={tabValue} index={1}>
            <UpstreamServers adminMode={true} onTabChange={handleTabChangeFromUpstreamServers} />
          </TabPanel>

          {/* Curated Servers Tab */}
          <TabPanel value={tabValue} index={2}>
            <CuratedServers adminMode={true} />
          </TabPanel>

          {/* Statistics Tab */}
          <TabPanel value={tabValue} index={3}>
            <Statistics />
          </TabPanel>

          {/* Logs Tab */}
          <TabPanel value={tabValue} index={4}>
            <Logs 
              selectedServerId={selectedLogServerId} 
              selectedServerName={selectedLogServerName} 
            />
          </TabPanel>

          {/* Users Tab */}
          <TabPanel value={tabValue} index={5}>
            <UserManagement />
          </TabPanel>
        </Paper>
      </Container>
    </Box>
  );
};
