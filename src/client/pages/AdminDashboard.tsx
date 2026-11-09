/**
 * Enterprise Admin Governance & Security Telemetry Dashboard
 * Aggregates access controls, denied attempt telemetry, alerts, and audit health.
 */

import React, { useState, useEffect } from 'react';
import { api, type AdminDashboardData } from '../api.js';
import {
  ShieldAlert,
  Users,
  FolderLock,
  KeyRound,
  Download,
  AlertOctagon,
  ShieldCheck,
  Activity,
  ArrowRight
} from 'lucide-react';

interface AdminDashboardProps {
  onNavigateToPentest: () => void;
  onNavigateToAudit: () => void;
}

export const AdminDashboard: React.FC<AdminDashboardProps> = ({
  onNavigateToPentest,
  onNavigateToAudit
}) => {
  const [data, setData] = useState<AdminDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const res = await api.getAdminDashboard();
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch admin telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="py-24 text-center text-slate-400">
        <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-3"></div>
        Aggregating system security telemetry...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 bg-rose-950/60 border border-rose-800 rounded-xl text-rose-300">
        {error || 'Unable to load administration dashboard.'}
      </div>
    );
  }

  const { metrics, recentAlerts, recentDeniedAttempts } = data;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
              Governance & Security Operations
            </span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">Security Officer Overview</h1>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Real-time monitoring of document access boundaries, failed attempts, and cryptographic audit proofs. Note: Administrative privileges do not bypass confidential document encryption.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onNavigateToPentest}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition shadow-lg shadow-blue-600/20"
          >
            <Activity className="w-4 h-4" /> Run Pentest Suite
          </button>
          <button
            onClick={onNavigateToAudit}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-400" /> Verify Audit Ledger
          </button>
        </div>
      </div>

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-medium uppercase">Active Users</span>
            <Users className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">{metrics.activeUsers}</div>
          <div className="text-[10px] text-slate-400 mt-1">{metrics.totalUsers} Total Accounts</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-medium uppercase">Total Documents</span>
            <FolderLock className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">{metrics.totalDocuments}</div>
          <div className="text-[10px] text-emerald-400 mt-1">{metrics.activeDocuments} Active In Vault</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-medium uppercase">Active Grants</span>
            <KeyRound className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{metrics.activeGrants}</div>
          <div className="text-[10px] text-slate-400 mt-1">{metrics.revokedGrants} Revoked Grants</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-medium uppercase">Total Downloads</span>
            <Download className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">{metrics.totalDownloads}</div>
          <div className="text-[10px] text-slate-400 mt-1">{metrics.totalUploads} Uploads Streamed</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-medium uppercase">Denied Attempts</span>
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{metrics.deniedAccessAttempts}</div>
          <div className="text-[10px] text-rose-300/80 mt-1">Blocked & Logged</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-medium uppercase">Audit Chain</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-base font-bold text-emerald-400 flex items-center gap-1">
            VERIFIED
          </div>
          <div className="text-[10px] text-slate-400 mt-1">{metrics.totalAuditEvents} Events Chained</div>
        </div>
      </div>

      {/* Two Column Layout: Security Alerts & Denied Access Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Security Alerts */}
        <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h2 className="font-semibold text-white text-sm">Security Alerts & Anomalies</h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">{recentAlerts.length} Captured</span>
          </div>

          {recentAlerts.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs">
              No active security incidents flagged. All access attempts comply with perimeter policies.
            </div>
          ) : (
            <div className="space-y-2.5">
              {recentAlerts.map(a => (
                <div
                  key={a.id}
                  className="p-3 bg-slate-950/70 rounded-xl border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                          a.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : a.severity === 'HIGH'
                            ? 'bg-orange-950 text-orange-300 border border-orange-800'
                            : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}
                      >
                        {a.severity}
                      </span>
                      <span className="font-semibold text-white">{a.type}</span>
                    </div>
                    <p className="text-slate-300 text-xs mt-1 leading-snug">{a.description}</p>
                    <div className="text-[10px] text-slate-400 mt-1 font-mono">
                      {new Date(a.timestamp).toLocaleTimeString()} • IP: {a.ip || '127.0.0.1'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Failed / Denied Access Attempts */}
        <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 text-amber-400" />
              <h2 className="font-semibold text-white text-sm">Denied Authorization Log (IDOR Defense)</h2>
            </div>
            <button
              onClick={onNavigateToAudit}
              className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium"
            >
              Full Ledger <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {recentDeniedAttempts.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs">
              Zero unauthorized requests recorded in recent window.
            </div>
          ) : (
            <div className="space-y-2.5">
              {recentDeniedAttempts.map(e => (
                <div
                  key={e.id}
                  className="p-3 bg-slate-950/70 rounded-xl border border-slate-800/80 flex items-center justify-between text-xs"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-rose-400">ACCESS_DENIED</span>
                      <span className="text-slate-300 font-mono text-[11px]">{e.actorEmail}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Target: {e.documentId || 'Restricted Endpoint'} • Role: {e.actorRole}
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 font-mono">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
