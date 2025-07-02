import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface User {
  id: number;
  username: string;
  is_active: boolean;
  is_admin: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isLoading: boolean;
  makeAuthenticatedRequest: (url: string, options?: RequestInit) => Promise<Response>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load token from localStorage on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('mcp_token');
    if (savedToken) {
      setToken(savedToken);
      // Validate token by fetching user info
      validateToken(savedToken);
    } else {
      setIsLoading(false);
    }
  }, []);

  const validateToken = async (tokenToValidate: string) => {
    try {
      const response = await fetch('/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${tokenToValidate}`,
        },
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
        setToken(tokenToValidate);
      } else {
        // Token is invalid
        localStorage.removeItem('mcp_token');
        setToken(null);
        setUser(null);
      }
    } catch (error) {
      console.error('Token validation failed:', error);
      localStorage.removeItem('mcp_token');
      setToken(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (username: string, password: string) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Login failed' }));
      throw new Error(errorData.error || 'Login failed');
    }

    const data = await response.json();
    
    // Store token and user data
    setToken(data.token);
    setUser(data.user);
    localStorage.setItem('mcp_token', data.token);
  };

  const logout = async () => {
    if (token) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
      } catch (error) {
        console.error('Logout request failed:', error);
      }
    }

    // Clear local state regardless of API call success
    setToken(null);
    setUser(null);
    localStorage.removeItem('mcp_token');
  };

  const makeAuthenticatedRequest = async (url: string, options: RequestInit = {}) => {
    if (!token) {
      throw new Error('No authentication token available');
    }

    const headers = {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
    };

    const response = await fetch(url, {
      ...options,
      headers,
    });

    // If we get a 401, the token might be expired
    if (response.status === 401) {
      logout();
      throw new Error('Authentication expired');
    }

    return response;
  };

  const value: AuthContextType = {
    user,
    token,
    login,
    logout,
    isLoading,
    makeAuthenticatedRequest,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
