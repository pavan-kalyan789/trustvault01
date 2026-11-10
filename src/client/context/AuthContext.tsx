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

export const DEMO_PROFILES = {
  admin: { email: 'admin@trustvault.local', role: 'admin' as const, label: 'Admin (CSO)' },
  owner: { email: 'owner@trustvault.local', role: 'owner' as const, label: 'Owner (Legal)' },
  viewer: { email: 'viewer@trustvault.local', role: 'viewer' as const, label: 'Viewer (Compliance)' },
  other: { email: 'other@trustvault.local', role: 'viewer' as const, label: 'Other Viewer (Contractor)' }
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
    let isMounted = true;

    const initializeSession = async () => {
      const existingToken = api.getToken();
      if (existingToken) {
        try {
          const data = await api.getMe();
          if (isMounted && data && data.user) {
            setUser(data.user);
            setLoading(false);
            return;
          }
        } catch {
          api.setToken(null);
        }
      }

      // Seamless entry: Auto-authenticate default Owner account without requiring sign in
      try {
        const demoAuth = await api.demoLogin('owner');
        if (isMounted && demoAuth && demoAuth.user) {
          setUser(demoAuth.user);
          setLoading(false);
          return;
        }
      } catch (err: any) {
        console.warn('[TrustVault] Auto-login fallback error:', err?.message || err);
      }

      if (isMounted) {
        setUser(null);
        setLoading(false);
      }
    };

    initializeSession();

    return () => {
      isMounted = false;
    };
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
    } catch {}
    // Reset directly to default demo account rather than dumping user to a blank login page
    try {
      const demoAuth = await api.demoLogin('owner');
      setUser(demoAuth.user);
    } catch {
      setUser(null);
    } finally {
      setError(null);
      setLoading(false);
    }
  };

  const switchDemoAccount = async (role: 'admin' | 'owner' | 'viewer' | 'other') => {
    setError(null);
    setLoading(true);
    try {
      const data = await api.demoLogin(role);
      if (data && data.success && data.user) {
        setUser(data.user);
      } else {
        throw new Error(data?.message || 'Authentication response missing valid user record.');
      }
    } catch (err: any) {
      const displayMsg = err.message || 'Unable to authenticate demo account. Please verify backend connection.';
      setError(displayMsg);
      throw err;
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
