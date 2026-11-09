/**
 * Authentication Context
 * Manages user session state, automatic token renewal, and 1-click demo role switching.
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

  const refreshUser = async () => {
    try {
      if (!api.getToken()) {
        setUser(null);
        setLoading(false);
        return;
      }
      const data = await api.getMe();
      setUser(data.user);
    } catch (err: any) {
      console.warn('[TrustVault Auth] Session restore failed:', err.message);
      api.setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // If no token exists on startup, default to owner for immediate exploration
    if (!api.getToken()) {
      switchDemoAccount('owner').catch(() => setLoading(false));
    } else {
      refreshUser();
    }
  }, []);

  const login = async (email: string, pass: string) => {
    setError(null);
    setLoading(true);
    try {
      const data = await api.login(email, pass);
      setUser(data.user);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await api.logout();
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const switchDemoAccount = async (role: 'admin' | 'owner' | 'viewer' | 'other') => {
    setError(null);
    setLoading(true);
    try {
      const creds = DEMO_CREDENTIALS[role];
      const data = await api.login(creds.email, creds.pass);
      setUser(data.user);
    } catch (err: any) {
      setError(err.message || 'Failed to switch demo account');
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
        refreshUser
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
