/**
 * Enterprise Login Screen
 * Zero-trust authentication with demo account quick-fill options.
 */

import React, { useState } from 'react';
import { useAuth, DEMO_CREDENTIALS } from '../context/AuthContext.js';
import { Shield, Lock, Eye, EyeOff, AlertTriangle, ArrowRight, UserCheck } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const { login, switchDemoAccount, error: authError } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    setLoading(true);
    try {
      await login(email, password);
    } catch (err: any) {
      setLocalError(err.message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = async (role: 'admin' | 'owner' | 'viewer' | 'other') => {
    setLocalError(null);
    const creds = DEMO_CREDENTIALS[role];
    setEmail(creds.email);
    setPassword(creds.pass);
    await switchDemoAccount(role);
  };

  const displayError = localError || authError;

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 relative overflow-hidden select-none">
      {/* Background ambient lighting */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>

      <div className="w-full max-w-md space-y-6 relative z-10">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center mx-auto shadow-xl shadow-blue-500/20 border border-blue-400/30">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">TrustVault</h1>
          <p className="text-xs text-slate-400 font-medium">
            Secure Documents • Controlled Access • Verifiable Trust
          </p>
        </div>

        {/* Login Box */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-3xl p-7 shadow-2xl space-y-5 text-xs">
          <div>
            <h2 className="text-sm font-semibold text-white">Sign In to Private Vault</h2>
            <p className="text-slate-400 text-xs mt-0.5">
              Enter credentials or pick a verified role below.
            </p>
          </div>

          {displayError && (
            <div className="p-3.5 bg-rose-950/60 border border-rose-700/60 rounded-xl text-rose-300 flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{displayError}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-slate-400 mb-1 font-medium">Account Email</label>
              <input
                type="email"
                placeholder="user@trustvault.local"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition text-xs"
                required
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">Vault Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-3.5 pr-10 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition text-xs"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-xl transition shadow-lg shadow-blue-600/20 disabled:opacity-50 text-xs flex items-center justify-center gap-2"
            >
              {loading ? 'Authenticating...' : 'Authenticate Identity'}
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          {/* Quick Demo Switcher */}
          <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-blue-400" />
              1-Click Demo Evaluation Profiles
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <button
                type="button"
                onClick={() => handleQuickLogin('admin')}
                className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-rose-700/60 hover:bg-rose-950/20 text-left transition"
              >
                <div className="font-semibold text-rose-300">Admin (CSO)</div>
                <div className="text-[10px] text-slate-400 font-mono">admin@trustvault.local</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickLogin('owner')}
                className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-emerald-700/60 hover:bg-emerald-950/20 text-left transition"
              >
                <div className="font-semibold text-emerald-300">Owner (Legal)</div>
                <div className="text-[10px] text-slate-400 font-mono">owner@trustvault.local</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickLogin('viewer')}
                className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-blue-700/60 hover:bg-blue-950/20 text-left transition"
              >
                <div className="font-semibold text-blue-300">Viewer (Auditor)</div>
                <div className="text-[10px] text-slate-400 font-mono">viewer@trustvault.local</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickLogin('other')}
                className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-amber-700/60 hover:bg-amber-950/20 text-left transition"
              >
                <div className="font-semibold text-amber-300">Other Viewer</div>
                <div className="text-[10px] text-slate-400 font-mono">other@trustvault.local</div>
              </button>
            </div>
          </div>
        </div>

        <div className="text-center text-[11px] text-slate-400">
          Hardware-enforced session hashing • SHA-256 non-repudiation
        </div>
      </div>
    </div>
  );
};
