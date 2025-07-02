import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Button,
} from '@mui/material';
import {
  Security,
  VpnKey,
} from '@mui/icons-material';
import { ChangePassword } from './ChangePassword';

export const AccountSettings: React.FC = () => {
  const [openChangePassword, setOpenChangePassword] = useState(false);

  const handleOpenChangePassword = () => {
    setOpenChangePassword(true);
  };

  const handleCloseChangePassword = () => {
    setOpenChangePassword(false);
  };

  return (
    <>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" alignItems="center" mb={2}>
            <Security sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6" component="h2">
              Account Settings
            </Typography>
          </Box>

          <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
            Manage your account settings and security.
          </Typography>

          <Box display="flex" gap={2} flexWrap="wrap">
            <Button
              variant="outlined"
              startIcon={<VpnKey />}
              onClick={handleOpenChangePassword}
            >
              Change Password
            </Button>
          </Box>
        </CardContent>
      </Card>

      <ChangePassword 
        open={openChangePassword} 
        onClose={handleCloseChangePassword} 
      />
    </>
  );
};
