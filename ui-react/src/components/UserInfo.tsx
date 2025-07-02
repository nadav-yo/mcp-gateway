import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  CircularProgress,
  Alert,
  Button,
  CardActions,
} from '@mui/material';
import { Person, AdminPanelSettings, Lock } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { ChangePassword } from './ChangePassword';

interface User {
  id: number;
  username: string;
  is_admin: boolean;
  is_active: boolean;
}

export const UserInfo: React.FC = () => {
  const { user } = useAuth();
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);

  const handleChangePasswordClick = () => {
    setChangePasswordOpen(true);
  };

  const handleChangePasswordClose = () => {
    setChangePasswordOpen(false);
  };

  if (!user) {
    return (
      <Card>
        <CardContent>
          <Alert severity="error">No user information available</Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
      <CardContent>
        <Box display="flex" alignItems="center" mb={2}>
          <Person sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h6" component="h2">
            User Information
          </Typography>
        </Box>
        
        {user && (
          <Box>
            <Box display="flex" alignItems="center" mb={1}>
              <Typography variant="body1" fontWeight="medium" sx={{ minWidth: 80 }}>
                Username:
              </Typography>
              <Typography variant="body1" sx={{ ml: 1 }}>
                {user.username}
              </Typography>
            </Box>
            
            <Box display="flex" alignItems="center" mb={1}>
              <Typography variant="body1" fontWeight="medium" sx={{ minWidth: 80 }}>
                Role:
              </Typography>
              <Box sx={{ ml: 1 }}>
                <Chip
                  icon={user.is_admin ? <AdminPanelSettings /> : <Person />}
                  label={user.is_admin ? 'Administrator' : 'User'}
                  color={user.is_admin ? 'primary' : 'default'}
                  size="small"
                />
              </Box>
            </Box>
            
            {user.is_active !== undefined && (
              <Box display="flex" alignItems="center">
                <Typography variant="body1" fontWeight="medium" sx={{ minWidth: 80 }}>
                  Status:
                </Typography>
                <Box sx={{ ml: 1 }}>
                  <Chip
                    label={user.is_active ? 'Active' : 'Inactive'}
                    color={user.is_active ? 'success' : 'error'}
                    size="small"
                  />
                </Box>
              </Box>
            )}
          </Box>
        )}
      </CardContent>
      <CardActions>
        <Button
          variant="outlined"
          startIcon={<Lock />}
          onClick={handleChangePasswordClick}
          size="small"
        >
          Change Password
        </Button>
      </CardActions>
    </Card>

    {/* Change Password Modal */}
    <ChangePassword
      open={changePasswordOpen}
      onClose={handleChangePasswordClose}
    />
  </>
  );
};
