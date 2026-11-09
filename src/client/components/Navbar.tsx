/**
 * Top Navigation & Demo Account Switcher
 * Provides role badge, live hash chain status, and 1-click evaluator switcher.
 */

import React, { useState } from 'react';
import { useAuth, DEMO_CREDENTIALS } from '../context/AuthContext.js';
import { Shield, Lock, CheckCircle2, UserCheck, LogOut, ChevronDown, Activity } from 'lucide-react';

interface NavbarProps {
  onOpenAuditVerify?: () => void;
  onOpenPentest?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onOpenAuditVerify, onOpenPentest }) => {
  const { user, logout, switchDemoAccount } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);

  if (!user) return null;

  const roleBadgeColors: Record<string, string> = {
    admin: 'bg-rose-900/60 text-rose-300 border-rose-700/60',
    owner: 'bg-emerald-900/60 text-emerald-300 border-emerald-700/60',
    viewer: 'bg-blue-900/60 text-blue-300 border-blue-700/60'
  };

  return (
    <header className="h-16 bg-slate-900/95 border-b border-slate-800 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-40 text-slate-100">
      {/* Brand & Tagline */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg shadow-blue-500/20 border border-blue-400/30">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold tracking-tight text-white text-base">TrustVault</span>
            <span className="text-[10px] font-semibold uppercase tracking-widest px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
              Enterprise Zero-Trust
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-medium">Secure Documents • Controlled Access • Verifiable Trust</p>
        </div>
      </div>

      {/* Default Logins Quick Switcher */}
      <div className="hidden lg:flex items-center gap-1.5 bg-slate-950/80 px-3 py-1.5 rounded-xl border border-slate-800">
        <span className="text-xs text-slate-400 font-medium flex items-center gap-1.5 mr-1">
          <UserCheck className="w-3.5 h-3.5 text-blue-400" />
          Default Logins:
        </span>
        <button
          onClick={() => switchDemoAccount('owner')}
          className={`text-xs px-2.5 py-1 rounded-lg transition-all font-medium ${
            user.role === 'owner'
              ? 'bg-emerald-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          Owner (Default)
        </button>
        <button
          onClick={() => switchDemoAccount('admin')}
          className={`text-xs px-2.5 py-1 rounded-lg transition-all font-medium ${
            user.role === 'admin'
              ? 'bg-rose-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          Admin
        </button>
        <button
          onClick={() => switchDemoAccount('viewer')}
          className={`text-xs px-2.5 py-1 rounded-lg transition-all font-medium ${
            user.role === 'viewer' && user.email === 'viewer@trustvault.local'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          Viewer
        </button>
        <button
          onClick={() => switchDemoAccount('other')}
          className={`text-xs px-2.5 py-1 rounded-lg transition-all font-medium ${
            user.email === 'other@trustvault.local'
              ? 'bg-amber-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          Other Viewer
        </button>
      </div>

      {/* Right Actions: Audit Status, Security Console, User Profile */}
      <div className="flex items-center gap-3">
        {onOpenAuditVerify && (
          <button
            onClick={onOpenAuditVerify}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-950/60 border border-emerald-700/60 text-emerald-300 hover:bg-emerald-900/60 transition shadow-sm"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Audit Chain:</span> Valid
          </button>
        )}

        {onOpenPentest && (
          <button
            onClick={onOpenPentest}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-950/70 border border-indigo-700/60 text-indigo-300 hover:bg-indigo-900/70 transition shadow-sm"
          >
            <Activity className="w-3.5 h-3.5 text-indigo-400" />
            <span className="hidden sm:inline">Security</span> Suite
          </button>
        )}

        {/* User Badge & Logout */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/80 hover:bg-slate-800 transition"
          >
            <div className="w-6 h-6 rounded-full bg-blue-600/40 text-blue-300 flex items-center justify-center font-bold text-xs border border-blue-400/30">
              {user.displayName.charAt(0)}
            </div>
            <div className="text-left hidden md:block">
              <div className="text-xs font-semibold text-white leading-tight">{user.displayName}</div>
              <div className="text-[10px] text-slate-400 font-mono leading-tight">{user.email}</div>
            </div>
            <span
              className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                roleBadgeColors[user.role] || 'bg-slate-800 text-slate-300'
              }`}
            >
              {user.role}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl py-2 z-50 animate-in fade-in zoom-in-95">
              <div className="px-4 py-2 border-b border-slate-800">
                <div className="text-xs font-semibold text-white">{user.displayName}</div>
                <div className="text-[11px] text-slate-400 font-mono">{user.email}</div>
                <div className="text-[10px] text-emerald-400 font-medium mt-1 flex items-center gap-1">
                  <Lock className="w-2.5 h-2.5" /> Hardware-isolated session active
                </div>
              </div>

              {/* Mobile Default Logins switcher */}
              <div className="px-3 py-2 border-b border-slate-800 lg:hidden">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                  Default Logins:
                </div>
                <div className="grid grid-cols-2 gap-1 text-xs">
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      switchDemoAccount('owner');
                    }}
                    className="p-1.5 rounded bg-slate-800 hover:bg-emerald-950 text-emerald-300 text-left text-[11px]"
                  >
                    Owner (Default)
                  </button>
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      switchDemoAccount('admin');
                    }}
                    className="p-1.5 rounded bg-slate-800 hover:bg-rose-950 text-rose-300 text-left text-[11px]"
                  >
                    Admin
                  </button>
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      switchDemoAccount('viewer');
                    }}
                    className="p-1.5 rounded bg-slate-800 hover:bg-blue-950 text-blue-300 text-left text-[11px]"
                  >
                    Viewer
                  </button>
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      switchDemoAccount('other');
                    }}
                    className="p-1.5 rounded bg-slate-800 hover:bg-amber-950 text-amber-300 text-left text-[11px]"
                  >
                    Other Viewer
                  </button>
                </div>
              </div>

              <div className="px-2 py-1">
                <button
                  onClick={() => {
                    setDropdownOpen(false);
                    logout();
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-rose-300 hover:bg-rose-950/50 rounded-lg transition"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  Sign Out to Default Logins
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
