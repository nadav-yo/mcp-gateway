import React from 'react';
import {
  Container,
  Typography,
  Box,
  Button,
  AppBar,
  Toolbar,
} from '@mui/material';
import { Logout } from '@mui/icons-material';
import { UserInfo } from './UserInfo';
import { TokenManagement } from './TokenManagement';
import { CuratedServers } from './CuratedServers';

interface UserPageProps {
  onLogout: () => void;
}

export const UserPage: React.FC<UserPageProps> = ({ onLogout }) => {
  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      onLogout();
    }
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

      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* User Information */}
          <Box>
            <UserInfo />
          </Box>

          {/* Token Management */}
          <Box>
            <TokenManagement />
          </Box>

          {/* Curated Servers */}
          <Box>
            <CuratedServers />
          </Box>
        </Box>
      </Container>
    </Box>
  );
};
