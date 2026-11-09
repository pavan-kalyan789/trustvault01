/**
 * Default Logins Screen
 * Pure default logins for TrustVault with zero external form inputs or errors.
 * 1-click authentication into verified evaluation profiles.
 */

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext.js';
import { Shield, UserCheck, ShieldAlert, FileText, Eye, AlertCircle, ArrowRight, Loader2 } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const { switchDemoAccount, error: authError, clearError } = useAuth();
  const [activeRole, setActiveRole] = useState<string | null>(null);

  const handleSelectDefaultLogin = async (role: 'admin' | 'owner' | 'viewer' | 'other') => {
    setActiveRole(role);
    clearError();
    try {
      await switchDemoAccount(role);
    } catch {
      // error handled in auth context
    } finally {
      setActiveRole(null);
    }
  };

  const defaultProfiles = [
    {
      role: 'owner' as const,
      name: 'Document Owner (Default)',
      email: 'owner@trustvault.local',
      title: 'Legal Counsel & Asset Owner',
      description: 'Full document ownership, uploads, versioning, permission grants, and immediate revocation.',
      badge: 'Default Workspace',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      borderColor: 'border-emerald-600/50 hover:border-emerald-400',
      bgColor: 'bg-emerald-950/20 hover:bg-emerald-950/40',
      buttonBg: 'bg-emerald-600 hover:bg-emerald-500 text-white',
      icon: FileText,
      iconColor: 'text-emerald-400'
    },
    {
      role: 'admin' as const,
      name: 'Chief Security Officer (CSO)',
      email: 'admin@trustvault.local',
      title: 'System Administrator',
      description: 'System-wide governance, audit chain verification, user deactivation, and security alerts.',
      badge: 'Security Controls',
      badgeColor: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
      borderColor: 'border-rose-600/40 hover:border-rose-400',
      bgColor: 'bg-rose-950/20 hover:bg-rose-950/40',
      buttonBg: 'bg-rose-600 hover:bg-rose-500 text-white',
      icon: ShieldAlert,
      iconColor: 'text-rose-400'
    },
    {
      role: 'viewer' as const,
      name: 'Auditor & Compliance Viewer',
      email: 'viewer@trustvault.local',
      title: 'Authorized Viewer',
      description: 'Read-only access to explicitly granted confidential files and personal access timeline.',
      badge: 'Authorized View',
      badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      borderColor: 'border-blue-600/40 hover:border-blue-400',
      bgColor: 'bg-blue-950/20 hover:bg-blue-950/40',
      buttonBg: 'bg-blue-600 hover:bg-blue-500 text-white',
      icon: Eye,
      iconColor: 'text-blue-400'
    },
    {
      role: 'other' as const,
      name: 'External Contractor Viewer',
      email: 'other@trustvault.local',
      title: 'Restricted Viewer',
      description: 'Isolated viewer used to verify cross-user isolation and proof of zero unauthorized metadata leak.',
      badge: 'Zero-Access Check',
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      borderColor: 'border-amber-600/40 hover:border-amber-400',
      bgColor: 'bg-amber-950/20 hover:bg-amber-950/40',
      buttonBg: 'bg-amber-600 hover:bg-amber-500 text-white',
      icon: UserCheck,
      iconColor: 'text-amber-400'
    }
  ];

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center p-4 sm:p-6 relative overflow-hidden select-none">
      {/* Background ambient glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[550px] h-[550px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>

      <div className="w-full max-w-2xl space-y-6 relative z-10">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center mx-auto shadow-xl shadow-blue-500/20 border border-blue-400/30">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">TrustVault</h1>
          <p className="text-xs sm:text-sm text-slate-400 font-medium max-w-md mx-auto">
            Secure Documents • Controlled Access • Verifiable Trust
          </p>
        </div>

        {/* Default Logins Card */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
          <div className="border-b border-slate-800/80 pb-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-white">Select Default Login</h2>
                <p className="text-slate-400 text-xs mt-0.5">
                  Click any verified default profile to instantly enter the vault.
                </p>
              </div>
              <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                1-Click Ready
              </span>
            </div>
          </div>

          {authError && (
            <div className="p-3 bg-rose-950/60 border border-rose-700/60 rounded-xl text-rose-300 text-xs flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{authError}</span>
            </div>
          )}

          {/* 4 Default Login Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            {defaultProfiles.map(p => {
              const Icon = p.icon;
              const isLoading = activeRole === p.role;

              return (
                <button
                  key={p.role}
                  type="button"
                  disabled={activeRole !== null}
                  onClick={() => handleSelectDefaultLogin(p.role)}
                  className={`p-4 rounded-2xl border text-left transition-all duration-200 flex flex-col justify-between ${p.borderColor} ${p.bgColor} group disabled:opacity-50`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-center">
                          <Icon className={`w-4 h-4 ${p.iconColor}`} />
                        </div>
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${p.badgeColor}`}>
                          {p.badge}
                        </span>
                      </div>
                    </div>

                    <div>
                      <div className="text-sm font-semibold text-white group-hover:text-blue-200 transition">
                        {p.name}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                        {p.email}
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                      {p.description}
                    </p>
                  </div>

                  <div className="pt-3 mt-3 border-t border-slate-800/60 flex items-center justify-between">
                    <span className="text-[11px] text-slate-400 font-medium">
                      Enter as {p.role.toUpperCase()}
                    </span>
                    <div className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1 transition ${p.buttonBg}`}>
                      {isLoading ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          <span>Entering...</span>
                        </>
                      ) : (
                        <>
                          <span>Launch</span>
                          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                        </>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Footer info */}
        <div className="text-center text-[11px] text-slate-500">
          Hardware-enforced session hashing • SHA-256 non-repudiation • Zero external dependencies
        </div>
      </div>
    </div>
  );
};
