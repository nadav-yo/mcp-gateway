import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider as MuiThemeProvider } from '@mui/material/styles';
import { CssBaseline, Box, CircularProgress } from '@mui/material';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider, useTheme } from './contexts/ThemeContext';
import { LoginPage } from './components/LoginPage';
import { UserPage } from './components/UserPage';
import { AdminPage } from './components/AdminPage';
import './App.css';

const AppContent: React.FC = () => {
  const { user, isLoading, logout } = useAuth();

  if (isLoading) {
    return (
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Router basename="/react">
      <Routes>
        <Route
          path="/login"
          element={
            user ? (
              <Navigate to={user.is_admin ? "/admin" : "/user"} replace />
            ) : (
              <LoginPage />
            )
          }
        />
        <Route
          path="/user"
          element={
            user ? (
              <UserPage onLogout={logout} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/admin"
          element={
            user && user.is_admin ? (
              <AdminPage onLogout={logout} />
            ) : user ? (
              <Navigate to="/user" replace />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/"
          element={
            <Navigate
              to={
                user
                  ? user.is_admin
                    ? "/admin"
                    : "/user"
                  : "/login"
              }
              replace
            />
          }
        />
      </Routes>
    </Router>
  );
};

const AppWithTheme: React.FC = () => {
  const { theme } = useTheme();
  
  return (
    <MuiThemeProvider theme={theme}>
      <CssBaseline />
      <AppContent />
    </MuiThemeProvider>
  );
};

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppWithTheme />
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
