/**
 * Authentication Context
 * Manages user session state, automatic session verification, and verified demo role switching.
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api.js';
import type { User, UserRole } from '../../server/types.js';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  login: (email: string, pass: string) => Promise<void>;
  logout: () => Promise<void>;
  switchDemoAccount: (role: 'admin' | 'owner' | 'viewer' | 'other') => Promise<void>;
  refreshUser: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const DEMO_CREDENTIALS = {
  admin: { email: 'admin@trustvault.local', pass: 'TrustVault2026!Admin', label: 'Admin (CSO)' },
  owner: { email: 'owner@trustvault.local', pass: 'TrustVault2026!Owner', label: 'Owner (Legal)' },
  viewer: { email: 'viewer@trustvault.local', pass: 'TrustVault2026!Viewer', label: 'Viewer (Compliance)' },
  other: { email: 'other@trustvault.local', pass: 'TrustVault2026!Other', label: 'Other Viewer (Contractor)' }
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const clearError = () => setError(null);

  const refreshUser = async () => {
    try {
      const token = api.getToken();
      if (!token) {
        setUser(null);
        setLoading(false);
        return;
      }
      const data = await api.getMe();
      if (data && data.user) {
        setUser(data.user);
      } else {
        api.setToken(null);
        setUser(null);
      }
    } catch (err: any) {
      console.warn('[TrustVault Auth] Session verify failed:', err.message);
      api.setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // If a saved token exists, verify it with backend
    const token = api.getToken();
    if (token) {
      refreshUser();
    } else {
      // Clean initial state: no error on fresh page load
      setUser(null);
      setLoading(false);
    }
  }, []);

  const login = async (email: string, pass: string) => {
    setError(null);
    setLoading(true);
    try {
      if (!email || !email.trim()) {
        throw new Error('Please enter your account email.');
      }
      if (!pass || !pass.trim()) {
        throw new Error('Please enter your password.');
      }
      const data = await api.login(email.trim(), pass);
      if (data && data.user) {
        setUser(data.user);
      } else {
        throw new Error('Server returned invalid session structure.');
      }
    } catch (err: any) {
      const msg = err.message || 'Authentication failed. Please verify credentials.';
      setError(msg);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await api.logout();
    } finally {
      api.setToken(null);
      setUser(null);
      setError(null);
      setLoading(false);
    }
  };

  const switchDemoAccount = async (role: 'admin' | 'owner' | 'viewer' | 'other') => {
    setError(null);
    setLoading(true);
    try {
      // First try dedicated verified demo-session endpoint
      const data = await api.demoLogin(role);
      if (data && data.user) {
        setUser(data.user);
      } else {
        throw new Error('Demo authentication returned invalid payload.');
      }
    } catch (err: any) {
      // Fallback: Authenticate with configured credentials
      try {
        const creds = DEMO_CREDENTIALS[role];
        const data = await api.login(creds.email, creds.pass);
        if (data && data.user) {
          setUser(data.user);
        } else {
          throw new Error('Fallback authentication failed.');
        }
      } catch (fallbackErr: any) {
        const displayMsg = fallbackErr.message || err.message || 'Unable to authenticate demo account.';
        setError(displayMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        error,
        login,
        logout,
        switchDemoAccount,
        refreshUser,
        clearError
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
