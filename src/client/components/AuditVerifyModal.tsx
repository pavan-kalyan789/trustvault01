/**
 * Cryptographic Audit Chain Verification Modal
 * Validates HMAC-SHA256 signatures, detects modification, deletion, or broken sequence.
 */

import React, { useState, useEffect } from 'react';
import { api, type VerificationResult } from '../api.js';
import {
  X,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Hash,
  Link,
  Lock
} from 'lucide-react';

interface AuditVerifyModalProps {
  onClose: () => void;
}

export const AuditVerifyModal: React.FC<AuditVerifyModalProps> = ({ onClose }) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runVerification = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.verifyAuditChain();
      setResult(data.verification);
    } catch (err: any) {
      setError(err.message || 'Verification execution failed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runVerification();
  }, []);

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-xl rounded-2xl shadow-2xl overflow-hidden flex flex-col text-xs text-slate-300">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-600/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-semibold text-white text-sm">Audit Chain Cryptographic Verification</h3>
              <p className="text-xs text-slate-400">HMAC-SHA256 Hash-Chained Security Ledger</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          {loading && (
            <div className="py-12 text-center text-slate-400">
              <RefreshCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-3" />
              <div className="text-sm font-semibold text-white">Recalculating HMAC Signatures...</div>
              <p className="text-xs text-slate-400 mt-1">
                Checking backward hash pointers and event payload canonical forms from genesis.
              </p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-rose-950/60 border border-rose-700/60 rounded-xl text-rose-300 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!loading && result && (
            <div className="space-y-5">
              {/* Status Banner */}
              <div
                className={`p-4 rounded-xl border flex items-center gap-3.5 ${
                  result.isValid
                    ? 'bg-emerald-950/50 border-emerald-700/60 text-emerald-300'
                    : 'bg-rose-950/50 border-rose-700/60 text-rose-300'
                }`}
              >
                {result.isValid ? (
                  <CheckCircle2 className="w-7 h-7 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-7 h-7 text-rose-400 shrink-0" />
                )}
                <div>
                  <div className="font-bold text-sm text-white">
                    {result.isValid
                      ? 'Audit Ledger Integrity Cryptographically Proven'
                      : 'Audit Chain Compromise Detected!'}
                  </div>
                  <div className="text-xs mt-0.5">
                    {result.isValid
                      ? `All ${result.verifiedCount} historical events matched calculated HMAC-SHA256 hashes without anomaly.`
                      : result.reason || 'Hash mismatch detected in audit chain.'}
                  </div>
                </div>
              </div>

              {/* Technical Hash Evidence */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3 font-mono">
                <div className="flex items-center justify-between text-[11px] pb-2 border-b border-slate-800">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <Link className="w-3.5 h-3.5 text-blue-400" /> Genesis Anchor Hash:
                  </span>
                  <span className="text-blue-300">00000000...genesis</span>
                </div>

                <div className="flex items-center justify-between text-[11px] pb-2 border-b border-slate-800">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <Hash className="w-3.5 h-3.5 text-emerald-400" /> Latest Verified Head Hash:
                  </span>
                  <span className="text-emerald-300 truncate max-w-[240px]">
                    {result.lastVerifiedHash || 'Verified'}
                  </span>
                </div>

                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-indigo-400" /> Total Verified Links:
                  </span>
                  <span className="text-white font-bold">{result.verifiedCount} / {result.totalEvents}</span>
                </div>
              </div>

              {/* Guarantees Box */}
              <div className="p-3.5 bg-slate-950/40 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 leading-relaxed">
                <strong className="text-white block mb-1">What This Proves:</strong>
                No past event has been deleted, inserted out of chronological sequence, or modified in database storage. Any altered action, timestamp, actor identity, or target ID breaks the recursive HMAC-SHA256 checksum immediately.
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex justify-between items-center">
          <button
            onClick={runVerification}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Re-verify Chain
          </button>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
