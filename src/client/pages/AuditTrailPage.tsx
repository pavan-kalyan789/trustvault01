/**
 * Tamper-Evident HMAC-SHA256 Audit Trail Ledger
 * Full immutable event ledger, outcome filters, hash inspection, and live verification.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import type { AuditEvent, AuditAction, AuditOutcome } from '../../server/types.js';
import {
  FileCheck2,
  ShieldCheck,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Hash,
  Eye,
  Lock,
  X
} from 'lucide-react';

interface AuditTrailPageProps {
  onOpenVerifyModal: () => void;
}

const AUDIT_ACTIONS = [
  'ALL',
  'LOGIN_SUCCESS',
  'LOGIN_FAILURE',
  'DOCUMENT_UPLOAD',
  'DOCUMENT_VIEW',
  'DOCUMENT_DOWNLOAD',
  'DOCUMENT_UPDATE',
  'DOCUMENT_VERSION_CREATED',
  'DOCUMENT_DELETE',
  'PERMISSION_GRANTED',
  'PERMISSION_REVOKED',
  'ACCESS_DENIED',
  'USER_CREATED',
  'USER_DISABLED',
  'ROLE_CHANGED',
  'AUDIT_VERIFICATION'
];

export const AuditTrailPage: React.FC<AuditTrailPageProps> = ({ onOpenVerifyModal }) => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAction, setSelectedAction] = useState('ALL');
  const [selectedOutcome, setSelectedOutcome] = useState<'ALL' | 'SUCCESS' | 'DENIED' | 'FAILURE'>('ALL');
  const [actorEmailSearch, setActorEmailSearch] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const res = await api.getAuditEvents({
        action: selectedAction === 'ALL' ? undefined : selectedAction,
        outcome: selectedOutcome === 'ALL' ? undefined : selectedOutcome,
        actorEmail: actorEmailSearch || undefined,
        limit: 150
      });
      setEvents(res.events);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchEvents();
    }, 200);
    return () => clearTimeout(timer);
  }, [selectedAction, selectedOutcome, actorEmailSearch]);

  const outcomeColors: Record<string, string> = {
    SUCCESS: 'bg-emerald-950/70 text-emerald-400 border-emerald-800/60',
    DENIED: 'bg-rose-950/70 text-rose-400 border-rose-800/60',
    FAILURE: 'bg-amber-950/70 text-amber-400 border-amber-800/60'
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
              Cryptographic Proof-of-Action
            </span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">Verifiable Audit Ledger</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Append-only HMAC-SHA256 hash-chain guaranteeing non-repudiation of all security transactions.
          </p>
        </div>

        <button
          onClick={onOpenVerifyModal}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition shadow-lg shadow-emerald-600/20 shrink-0"
        >
          <ShieldCheck className="w-4 h-4" /> Verify Chain Integrity
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-slate-900/90 p-4 rounded-2xl border border-slate-800 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div>
            <label className="block text-slate-400 mb-1 font-medium">Search Actor Email</label>
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter by actor..."
                value={actorEmailSearch}
                onChange={e => setActorEmailSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">Filter by Action</label>
            <select
              value={selectedAction}
              onChange={e => setSelectedAction(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
            >
              {AUDIT_ACTIONS.map(a => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">Outcome Status</label>
            <div className="grid grid-cols-4 gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800">
              {(['ALL', 'SUCCESS', 'DENIED', 'FAILURE'] as const).map(out => (
                <button
                  key={out}
                  onClick={() => setSelectedOutcome(out)}
                  className={`py-1 rounded-lg font-medium text-[11px] transition ${
                    selectedOutcome === out
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {out}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Audit Events Ledger Table */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 overflow-hidden shadow-xl text-xs">
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <span className="font-semibold text-white">Event Log Stream ({events.length} records)</span>
          <span className="text-[11px] text-slate-400 font-mono">HMAC Secret Active</span>
        </div>

        {loading ? (
          <div className="py-20 text-center text-slate-400">
            <RefreshCw className="w-7 h-7 text-blue-500 animate-spin mx-auto mb-2" />
            Reading cryptographic records...
          </div>
        ) : events.length === 0 ? (
          <div className="py-16 text-center text-slate-400">No audit events match current criteria.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-slate-300">
              <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Outcome</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Target / Doc ID</th>
                  <th className="py-3 px-4">Event Hash (HMAC)</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                {events.map(e => (
                  <tr key={e.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(e.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>
                    <td className="py-3 px-4 font-sans font-bold text-white">
                      {e.action}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`text-[9px] font-bold px-2 py-0.5 rounded border uppercase ${
                          outcomeColors[e.outcome] || 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {e.outcome}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-white font-sans font-medium text-xs truncate max-w-[140px]">
                        {e.actorEmail}
                      </div>
                      <div className="text-[10px] text-slate-500 font-sans uppercase">[{e.actorRole}]</div>
                    </td>
                    <td className="py-3 px-4 text-slate-400 truncate max-w-[120px]">
                      {e.documentId || e.targetUserId || '-'}
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[10px] text-emerald-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                        {e.hash.substring(0, 12)}...
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(e)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                        title="View raw cryptographic event"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Raw Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 w-full max-w-xl rounded-2xl shadow-2xl overflow-hidden flex flex-col text-xs text-slate-300">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <Hash className="w-4 h-4 text-emerald-400" />
                <h3 className="font-semibold text-white text-sm">Audit Record Cryptographic Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 overflow-y-auto max-h-[75vh]">
              <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold">Event ID</span>
                  <div className="font-mono text-white text-[11px] truncate">{selectedEvent.id}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold">Request ID</span>
                  <div className="font-mono text-white text-[11px] truncate">{selectedEvent.requestId}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold">Client IP</span>
                  <div className="font-mono text-white text-[11px]">{selectedEvent.ip}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold">Timestamp</span>
                  <div className="font-mono text-white text-[11px]">{selectedEvent.timestamp}</div>
                </div>
              </div>

              {/* Hash Link */}
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2 font-mono text-[11px]">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase font-bold block mb-0.5">
                    Previous Hash Pointer (prevHash):
                  </span>
                  <div className="text-blue-300 bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 break-all select-all">
                    {selectedEvent.prevHash}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase font-bold block mb-0.5">
                    HMAC-SHA256 Signature (hash):
                  </span>
                  <div className="text-emerald-300 bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 break-all select-all font-bold">
                    {selectedEvent.hash}
                  </div>
                </div>
              </div>

              {/* Metadata JSON */}
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                  Canonical Event Metadata (Non-Sensitive)
                </span>
                <pre className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-200 overflow-x-auto">
                  {JSON.stringify(selectedEvent.metadata, null, 2)}
                </pre>
              </div>
            </div>

            <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
