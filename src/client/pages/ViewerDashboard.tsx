/**
 * Viewer Restricted Dashboard
 * Displays only explicitly shared documents; strictly enforces zero-knowledge of unshared documents.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useAuth } from '../context/AuthContext.js';
import type { DocumentRecord } from '../../server/types.js';
import {
  FolderLock,
  Download,
  Eye,
  ShieldCheck,
  Lock,
  FileText,
  AlertCircle
} from 'lucide-react';

interface ViewerDashboardProps {
  onSelectDocument: (doc: DocumentRecord) => void;
}

export const ViewerDashboard: React.FC<ViewerDashboardProps> = ({ onSelectDocument }) => {
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
      {/* Banner */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
            Auditor / Viewer Portal
          </span>
        </div>
        <h1 className="text-xl font-bold text-white tracking-tight">
          Documents Shared With {user?.displayName}
        </h1>
        <p className="text-xs text-slate-400 mt-1 max-w-xl">
          You are authenticated as an external or compliance viewer. You can inspect and download documents explicitly shared with you. You cannot upload, modify, or reshare documents.
        </p>
      </div>

      {/* Security Boundary Notice */}
      <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-800/60 flex items-start gap-3 text-xs text-blue-200">
        <ShieldCheck className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-white block mb-0.5">Zero-Knowledge Isolation Enforced:</strong>
          Our server-side queries only return documents where your user identity holds an active, unexpired permission record. All unshared documents are hidden and return 404 Not Found to prevent metadata reconnaissance.
        </div>
      </div>

      {/* Shared Documents Table */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <FolderLock className="w-4 h-4 text-blue-400" />
            <h2 className="font-semibold text-white text-sm">
              Accessible Documents ({documents.length})
            </h2>
          </div>
          <span className="text-[11px] text-slate-400">READ Permissions Active</span>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs">Loading authorized records...</div>
        ) : documents.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs space-y-2">
            <Lock className="w-8 h-8 text-slate-600 mx-auto" />
            <div className="font-semibold text-slate-300">No Documents Shared With You</div>
            <p className="text-slate-400 max-w-md mx-auto text-[11px]">
              Switch to the Document Owner role using the top demo switcher to grant this account READ rights to any document.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {documents.map(doc => (
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
                      <span
                        className="font-semibold text-white text-xs hover:text-blue-400 cursor-pointer"
                        onClick={() => onSelectDocument(doc)}
                      >
                        {doc.name}
                      </span>
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/60">
                        v{doc.version}
                      </span>
                      <span className="text-[9px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {doc.category}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-3">
                      <span>Owner: {doc.ownerEmail}</span>
                      <span>•</span>
                      <span>{(doc.size / 1024).toFixed(1)} KB</span>
                      <span>•</span>
                      <span>Shared Access: READ</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleDownload(doc)}
                    disabled={downloadingId === doc.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition shadow-sm disabled:opacity-50"
                  >
                    <Download className="w-3.5 h-3.5" />
                    {downloadingId === doc.id ? 'Streaming...' : 'Download'}
                  </button>
                  <button
                    onClick={() => onSelectDocument(doc)}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                    title="View details"
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
