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
} from '@mui/material';
import { 
  Logout,
  Dashboard,
  LibraryBooks,
} from '@mui/icons-material';
import { UserInfo } from './UserInfo';
import { TokenManagement } from './TokenManagement';
import { UserCuratedServers } from './UserCuratedServers';

interface UserPageProps {
  onLogout: () => void;
}

export const UserPage: React.FC<UserPageProps> = ({ onLogout }) => {
  const [activeTab, setActiveTab] = useState(0);

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      onLogout();
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            MCP Gateway - User Dashboard
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

      <Container maxWidth="lg" sx={{ mt: 2, mb: 4 }}>
        <Box sx={{ width: '100%' }}>
          {/* Tabs Navigation */}
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={activeTab} onChange={handleTabChange} aria-label="user dashboard tabs">
              <Tab 
                icon={<Dashboard />} 
                label="Dashboard" 
                iconPosition="start"
              />
              <Tab 
                icon={<LibraryBooks />} 
                label="Curated Servers" 
                iconPosition="start"
              />
            </Tabs>
          </Box>

          {/* Tab Content */}
          <Box sx={{ mt: 3 }}>
            {/* Dashboard Tab */}
            {activeTab === 0 && (
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
            )}

            {/* Curated Servers Tab */}
            {activeTab === 1 && (
              <Box>
                <UserCuratedServers />
              </Box>
            )}
          </Box>
        </Box>
      </Container>
    </Box>
  );
};
