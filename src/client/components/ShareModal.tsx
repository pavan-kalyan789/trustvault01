/**
 * Enterprise Share Document Modal
 * Explicit recipient selection, READ/EDIT permission, expiration,
 * and immediate revocation of existing grants.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import type { DocumentRecord, DocumentGrant, User } from '../../server/types.js';
import {
  X,
  Share2,
  Shield,
  Clock,
  Trash2,
  AlertTriangle,
  CheckCircle,
  UserCheck
} from 'lucide-react';

interface ShareModalProps {
  document: DocumentRecord;
  onClose: () => void;
  onGrantUpdated: () => void;
}

export const ShareModal: React.FC<ShareModalProps> = ({
  document: doc,
  onClose,
  onGrantUpdated
}) => {
  const [grants, setGrants] = useState<DocumentGrant[]>([]);
  const [availableUsers, setAvailableUsers] = useState<User[]>([]);
  const [selectedEmail, setSelectedEmail] = useState('');
  const [permissionLevel, setPermissionLevel] = useState<'READ' | 'EDIT'>('READ');
  const [expirationDays, setExpirationDays] = useState<number>(30);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const fetchGrantsAndUsers = async () => {
    try {
      const [grantsRes, usersRes] = await Promise.all([
        api.getPermissions(doc.id),
        api.getUsers()
      ]);
      setGrants(grantsRes.grants);
      // Filter out document owner from recipient list
      setAvailableUsers(usersRes.users.filter(u => u.id !== doc.ownerId));
      if (usersRes.users.length > 0 && !selectedEmail) {
        const firstRecipient = usersRes.users.find(u => u.id !== doc.ownerId);
        if (firstRecipient) setSelectedEmail(firstRecipient.email);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load grants.');
    }
  };

  useEffect(() => {
    fetchGrantsAndUsers();
  }, [doc.id]);

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!selectedEmail) {
      setError('Please select or specify a recipient email.');
      return;
    }

    setLoading(true);
    try {
      let expiresAt: string | null = null;
      if (expirationDays > 0) {
        expiresAt = new Date(Date.now() + expirationDays * 24 * 3600 * 1000).toISOString();
      }

      await api.grantPermission(doc.id, selectedEmail, permissionLevel, expiresAt);
      setSuccess(`Permission successfully granted to ${selectedEmail}.`);
      await fetchGrantsAndUsers();
      onGrantUpdated();
    } catch (err: any) {
      setError(err.message || 'Failed to grant permission.');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (grantId: string, granteeEmail: string) => {
    setError(null);
    setSuccess(null);
    setRevokingId(grantId);
    try {
      await api.revokePermission(doc.id, grantId);
      setSuccess(`Immediate revocation successful: Access removed for ${granteeEmail}.`);
      await fetchGrantsAndUsers();
      onGrantUpdated();
    } catch (err: any) {
      setError(err.message || 'Failed to revoke permission.');
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Share2 className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-white text-sm">Manage Document Permissions</h3>
              <p className="text-xs text-slate-400 truncate max-w-sm">{doc.name}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 text-slate-200 text-xs">
          {error && (
            <div className="p-3 bg-rose-950/60 border border-rose-700/60 rounded-xl text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="p-3 bg-emerald-950/60 border border-emerald-700/60 rounded-xl text-emerald-300 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{success}</span>
            </div>
          )}

          {/* Grant Form */}
          <form onSubmit={handleGrant} className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-4">
            <div className="font-semibold text-white text-xs flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-blue-400" />
              Grant Explicit Access
            </div>

            <div>
              <label className="block text-slate-400 mb-1 font-medium">Select Recipient User</label>
              <select
                value={selectedEmail}
                onChange={e => setSelectedEmail(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
              >
                {availableUsers.map(u => (
                  <option key={u.id} value={u.email}>
                    {u.displayName} ({u.email}) — [{u.role}]
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Permission Level</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setPermissionLevel('READ')}
                    className={`py-2 px-3 rounded-lg border font-medium text-center transition ${
                      permissionLevel === 'READ'
                        ? 'bg-blue-600 text-white border-blue-500'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    READ
                  </button>
                  <button
                    type="button"
                    onClick={() => setPermissionLevel('EDIT')}
                    className={`py-2 px-3 rounded-lg border font-medium text-center transition ${
                      permissionLevel === 'EDIT'
                        ? 'bg-indigo-600 text-white border-indigo-500'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    EDIT
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Expiration Period</label>
                <select
                  value={expirationDays}
                  onChange={e => setExpirationDays(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  <option value={7}>7 Days</option>
                  <option value={30}>30 Days</option>
                  <option value={90}>90 Days</option>
                  <option value={0}>No Expiration (Indefinite)</option>
                </select>
              </div>
            </div>

            <div className="text-[11px] text-slate-400 flex items-start gap-1.5 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <Shield className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
              <span>
                <strong>Explicit Grant:</strong> Access is tracked in the immutable audit ledger. Revocation will take effect immediately for all subsequent download or view requests.
              </span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 px-4 rounded-lg transition shadow-md shadow-blue-600/20 disabled:opacity-50"
            >
              {loading ? 'Committing Grant...' : 'Confirm & Grant Permission'}
            </button>
          </form>

          {/* Active Grants List */}
          <div>
            <div className="font-semibold text-white text-xs mb-3 flex items-center justify-between">
              <span>Existing Permission Grants ({grants.length})</span>
              <span className="text-[10px] text-slate-400">Authoritative Database Record</span>
            </div>

            {grants.length === 0 ? (
              <div className="p-6 text-center text-slate-400 bg-slate-950/40 rounded-xl border border-slate-800">
                No external permissions granted. Only the document owner has access.
              </div>
            ) : (
              <div className="space-y-2">
                {grants.map(g => (
                  <div
                    key={g.id}
                    className={`p-3 rounded-xl border flex items-center justify-between ${
                      g.isActive
                        ? 'bg-slate-950/70 border-slate-800'
                        : 'bg-slate-950/30 border-slate-900 opacity-60'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-white">{g.granteeEmail}</span>
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                            g.permissionLevel === 'EDIT'
                              ? 'bg-indigo-900/80 text-indigo-300 border border-indigo-700/60'
                              : 'bg-blue-900/80 text-blue-300 border border-blue-700/60'
                          }`}
                        >
                          {g.permissionLevel}
                        </span>
                        {g.isActive ? (
                          <span className="text-[9px] font-semibold text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/60">
                            ACTIVE
                          </span>
                        ) : (
                          <span className="text-[9px] font-semibold text-rose-400 bg-rose-950/60 px-1.5 py-0.5 rounded border border-rose-800/60">
                            REVOKED
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5 flex items-center gap-2">
                        <span>Granted {new Date(g.createdAt).toLocaleDateString()}</span>
                        {g.expiresAt && (
                          <span className="flex items-center gap-1">
                            <Clock className="w-2.5 h-2.5" /> Expires {new Date(g.expiresAt).toLocaleDateString()}
                          </span>
                        )}
                        {g.revokedAt && (
                          <span className="text-rose-400">
                            Revoked {new Date(g.revokedAt).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>

                    {g.isActive && (
                      <button
                        onClick={() => handleRevoke(g.id, g.granteeEmail)}
                        disabled={revokingId === g.id}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-rose-400 hover:text-white hover:bg-rose-600 transition text-[11px] font-medium border border-rose-800/60"
                        title="Immediately revoke access"
                      >
                        <Trash2 className="w-3 h-3" />
                        {revokingId === g.id ? 'Revoking...' : 'Revoke'}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
