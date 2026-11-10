/**
 * Document Owner Dashboard
 * Real-time management of owned documents, permission sharing, and access revocation.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useAuth } from '../context/AuthContext.js';
import type { DocumentRecord, DocumentGrant } from '../../server/types.js';
import {
  FolderLock,
  Share2,
  Upload,
  Download,
  Eye,
  Trash2,
  KeyRound,
  FileText,
  Shield,
  Clock
} from 'lucide-react';

interface OwnerDashboardProps {
  onOpenUpload: () => void;
  onSelectDocument: (doc: DocumentRecord) => void;
  onShareDocument: (doc: DocumentRecord) => void;
}

export const OwnerDashboard: React.FC<OwnerDashboardProps> = ({
  onOpenUpload,
  onSelectDocument,
  onShareDocument
}) => {
  const { user } = useAuth();
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchDocs = async () => {
    try {
      setLoading(true);
      const res = await api.getDocuments();
      setDocuments(res.documents);
    } catch (err: any) {
      setActionError(err.message || 'Failed to load documents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocs();
  }, [user?.id]);

  const ownedDocs = documents.filter(d => d.ownerId === user?.id);
  const sharedWithMe = documents.filter(d => d.ownerId !== user?.id);

  const handleDownload = async (doc: DocumentRecord) => {
    setActionError(null);
    setDownloadingId(doc.id);
    try {
      await api.downloadDocument(doc.id, doc.originalFilename);
    } catch (err: any) {
      setActionError(`Download Error: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {actionError && (
        <div className="p-3 bg-red-950/40 border border-red-500/30 rounded-xl text-red-300 text-xs flex items-center justify-between">
          <span>{actionError}</span>
          <button onClick={() => setActionError(null)} className="text-red-400 hover:text-red-200 text-xs font-bold">Dismiss</button>
        </div>
      )}
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
              Document Custodian Portal
            </span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Welcome back, {user?.displayName}
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            You hold exclusive control over your encrypted documents. Grant explicit READ or EDIT rights, configure expiration windows, and trigger instantaneous revocation.
          </p>
        </div>

        <button
          onClick={onOpenUpload}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition shadow-lg shadow-blue-600/20 shrink-0"
        >
          <Upload className="w-4 h-4" /> Upload Secure Document
        </button>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="text-[11px] font-medium text-slate-400 uppercase mb-1">My Vault Documents</div>
          <div className="text-2xl font-bold text-white">{ownedDocs.length}</div>
          <div className="text-[10px] text-slate-400 mt-1">Stored with SHA-256 verification</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="text-[11px] font-medium text-slate-400 uppercase mb-1">Shared With Me</div>
          <div className="text-2xl font-bold text-indigo-400">{sharedWithMe.length}</div>
          <div className="text-[10px] text-slate-400 mt-1">Cross-department grants</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="text-[11px] font-medium text-slate-400 uppercase mb-1">Storage Security</div>
          <div className="text-2xl font-bold text-emerald-400">Mode 0600</div>
          <div className="text-[10px] text-slate-400 mt-1">Isolated private storage keys</div>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="text-[11px] font-medium text-slate-400 uppercase mb-1">Revocation Status</div>
          <div className="text-2xl font-bold text-blue-400">Instant</div>
          <div className="text-[10px] text-slate-400 mt-1">Zero-latency DB enforcement</div>
        </div>
      </div>

      {/* Owned Documents Table */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <FolderLock className="w-4 h-4 text-blue-400" />
            <h2 className="font-semibold text-white text-sm">My Vault Documents ({ownedDocs.length})</h2>
          </div>
          <span className="text-[11px] text-slate-400">Protected by Document-Level ACLs</span>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs">Loading documents...</div>
        ) : ownedDocs.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            No documents uploaded yet. Click "Upload Secure Document" to start.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {ownedDocs.map(doc => (
              <div
                key={doc.id}
                className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/30 px-3 rounded-xl transition"
              >
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0 mt-0.5">
                    <FileText className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white text-xs hover:text-blue-400 cursor-pointer" onClick={() => onSelectDocument(doc)}>
                        {doc.name}
                      </span>
                      <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-blue-900/60 text-blue-300 border border-blue-700/60">
                        v{doc.version}
                      </span>
                      <span className="text-[9px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {doc.category}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-3">
                      <span>{doc.originalFilename}</span>
                      <span>•</span>
                      <span>{(doc.size / 1024).toFixed(1)} KB</span>
                      <span>•</span>
                      <span>{new Date(doc.createdAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleDownload(doc)}
                    disabled={downloadingId === doc.id}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                    title="Download document"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => onShareDocument(doc)}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition shadow-sm"
                  >
                    <Share2 className="w-3.5 h-3.5" /> Share
                  </button>
                  <button
                    onClick={() => onSelectDocument(doc)}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                    title="View details and audit"
                  >
                    <Eye className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
