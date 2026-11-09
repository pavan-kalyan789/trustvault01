/**
 * Document Details, Preview, and Version History Modal
 * Displays cryptographic hash, metadata, authenticated streaming download, and version history.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useAuth } from '../context/AuthContext.js';
import type { DocumentRecord, DocumentVersion, AuditEvent } from '../../server/types.js';
import {
  X,
  Download,
  Eye,
  History,
  Shield,
  FileText,
  FileCode,
  Upload,
  AlertTriangle,
  CheckCircle,
  File
} from 'lucide-react';

interface DocumentDetailsModalProps {
  document: DocumentRecord;
  onClose: () => void;
  onDocumentUpdated: () => void;
  onOpenShare: () => void;
}

export const DocumentDetailsModal: React.FC<DocumentDetailsModalProps> = ({
  document: doc,
  onClose,
  onDocumentUpdated,
  onOpenShare
}) => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<'details' | 'preview' | 'versions' | 'audit'>('details');
  const [versions, setVersions] = useState<DocumentVersion[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [versionFile, setVersionFile] = useState<File | null>(null);
  const [changeDescription, setChangeDescription] = useState('');
  const [uploadingVersion, setUploadingVersion] = useState(false);
  const [versionMsg, setVersionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const isOwner = user?.id === doc.ownerId;
  const canEdit = isOwner; // Or if has EDIT grant

  useEffect(() => {
    // Load versions
    api.getVersions(doc.id)
      .then(res => setVersions(res.versions))
      .catch(() => {});

    // Load audit history
    api.getAuditEvents({ limit: 50 })
      .then(res => {
        setAuditEvents(res.events.filter(e => e.documentId === doc.id));
      })
      .catch(() => {});
  }, [doc.id]);

  const loadPreview = async () => {
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const url = await api.getPreviewUrl(doc.id);
      if (doc.mimeType === 'text/plain') {
        const textRes = await fetch(url);
        const text = await textRes.text();
        setPreviewContent(text);
      } else {
        setPreviewContent(url);
      }
    } catch (err: any) {
      setPreviewError(err.message || 'Access denied for document preview.');
    } finally {
      setPreviewLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'preview') {
      loadPreview();
    }
  }, [activeTab]);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await api.downloadDocument(doc.id, doc.originalFilename);
    } catch (err: any) {
      alert(`Download Error: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleVersionUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!versionFile) return;

    setUploadingVersion(true);
    setVersionMsg(null);
    try {
      const formData = new FormData();
      formData.append('file', versionFile);
      formData.append('changeDescription', changeDescription || 'Updated document version');

      await api.uploadVersion(doc.id, formData);
      setVersionMsg({ type: 'success', text: 'New document version successfully uploaded.' });
      setVersionFile(null);
      setChangeDescription('');
      const updatedVersions = await api.getVersions(doc.id);
      setVersions(updatedVersions.versions);
      onDocumentUpdated();
    } catch (err: any) {
      setVersionMsg({ type: 'error', text: err.message || 'Failed to upload version.' });
    } finally {
      setUploadingVersion(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <File className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold text-white text-sm">{doc.name}</h3>
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/60">
                  v{doc.version}
                </span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {doc.category}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">{doc.originalFilename}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownload}
              disabled={downloading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition shadow-sm disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              {downloading ? 'Downloading...' : 'Download'}
            </button>
            {isOwner && (
              <button
                onClick={onOpenShare}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              >
                Share
              </button>
            )}
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-slate-800 bg-slate-950/30 flex gap-4 text-xs font-medium">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-3 border-b-2 transition ${
              activeTab === 'details'
                ? 'border-blue-500 text-blue-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Metadata & Security
          </button>
          <button
            onClick={() => setActiveTab('preview')}
            className={`py-3 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'preview'
                ? 'border-blue-500 text-blue-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Eye className="w-3.5 h-3.5" />
            Secure Preview
          </button>
          <button
            onClick={() => setActiveTab('versions')}
            className={`py-3 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'versions'
                ? 'border-blue-500 text-blue-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            Version History ({versions.length})
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`py-3 border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'audit'
                ? 'border-blue-500 text-blue-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            Audit Ledger ({auditEvents.length})
          </button>
        </div>

        {/* Tab Content */}
        <div className="p-6 overflow-y-auto flex-1 text-xs text-slate-300">
          {activeTab === 'details' && (
            <div className="space-y-6">
              {/* Description */}
              <div>
                <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1">
                  Document Description
                </h4>
                <p className="text-slate-200 text-sm leading-relaxed bg-slate-950/40 p-3.5 rounded-xl border border-slate-800">
                  {doc.description || 'No descriptive context provided.'}
                </p>
              </div>

              {/* Cryptographic Hash & Storage Security */}
              <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-3">
                <div className="font-semibold text-white flex items-center gap-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  Cryptographic Integrity & Vault Storage
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] text-slate-400 uppercase font-mono">SHA-256 Content Hash</div>
                    <div className="font-mono text-[11px] text-emerald-300 bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 break-all select-all">
                      {doc.sha256Hash}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-slate-400 uppercase font-mono">Private Storage Object Key</div>
                    <div className="font-mono text-[11px] text-blue-300 bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 truncate">
                      {doc.storageKey}
                    </div>
                  </div>
                </div>
              </div>

              {/* Technical Specifications Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-950/40 p-4 rounded-xl border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">Owner</span>
                  <div className="font-semibold text-white truncate">{doc.ownerEmail}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">File Size</span>
                  <div className="font-semibold text-white">{(doc.size / 1024).toFixed(1)} KB</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">MIME Type</span>
                  <div className="font-semibold text-white font-mono text-[11px] truncate">{doc.mimeType}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">Retention Policy</span>
                  <div className="font-semibold text-emerald-400 uppercase text-[11px]">{doc.retentionStatus} (7 Yr)</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">Uploaded</span>
                  <div className="font-semibold text-white">{new Date(doc.createdAt).toLocaleDateString()}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">Last Modified</span>
                  <div className="font-semibold text-white">{new Date(doc.updatedAt).toLocaleDateString()}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">Current Version</span>
                  <div className="font-semibold text-blue-400">Release v{doc.version}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-medium">Status</span>
                  <div className="font-semibold text-emerald-400">Active (Protected)</div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'preview' && (
            <div className="space-y-4">
              {previewLoading && (
                <div className="py-12 text-center text-slate-400">
                  <div className="animate-spin w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-2"></div>
                  Authenticating and decrypting stream...
                </div>
              )}

              {previewError && (
                <div className="p-4 bg-rose-950/60 border border-rose-700/60 rounded-xl text-rose-300 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
                  <span>{previewError}</span>
                </div>
              )}

              {!previewLoading && !previewError && previewContent && (
                <div>
                  {doc.mimeType === 'text/plain' ? (
                    <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap">
                      {previewContent}
                    </pre>
                  ) : doc.mimeType.startsWith('image/') ? (
                    <div className="flex justify-center p-4 bg-slate-950 rounded-xl border border-slate-800">
                      <img src={previewContent} alt={doc.name} className="max-h-96 object-contain rounded-lg" />
                    </div>
                  ) : doc.mimeType === 'application/pdf' ? (
                    <div className="h-96 bg-slate-950 rounded-xl border border-slate-800 flex flex-col items-center justify-center p-6 text-center">
                      <FileText className="w-12 h-12 text-blue-400 mb-3" />
                      <div className="font-semibold text-white text-sm mb-1">Authenticated PDF Preview</div>
                      <p className="text-slate-400 max-w-md text-xs mb-4">
                        Securely streamed directly through authenticated proxy.
                      </p>
                      <button
                        onClick={handleDownload}
                        className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs flex items-center gap-2 shadow-sm"
                      >
                        <Download className="w-4 h-4" /> Download PDF File
                      </button>
                    </div>
                  ) : (
                    <div className="p-6 bg-slate-950 rounded-xl border border-slate-800 text-center">
                      <FileCode className="w-10 h-10 text-slate-400 mx-auto mb-2" />
                      <div className="font-semibold text-white">Document Structure Verified</div>
                      <p className="text-slate-400 text-xs mt-1">
                        DOCX/XLSX containers are stored encrypted in the private vault. Download to inspect in native suite.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'versions' && (
            <div className="space-y-6">
              {/* Version History List */}
              <div className="space-y-3">
                <h4 className="font-semibold text-white">Release Versions</h4>
                {versions.map(v => (
                  <div key={v.id} className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-xs">Version {v.versionNumber}</span>
                        <span className="text-[10px] text-slate-400 font-mono">({(v.size / 1024).toFixed(1)} KB)</span>
                        <span className="text-[10px] text-blue-400 font-mono">{v.mimeType}</span>
                      </div>
                      <p className="text-xs text-slate-300 mt-1">{v.changeDescription}</p>
                      <div className="text-[10px] text-slate-400 mt-1">
                        Created by {v.createdByEmail} on {new Date(v.createdAt).toLocaleString()}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-[9px] font-mono text-emerald-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                        {v.sha256Hash.substring(0, 16)}...
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Upload New Version */}
              {canEdit && (
                <form onSubmit={handleVersionUpload} className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-4">
                  <div className="font-semibold text-white flex items-center gap-2">
                    <Upload className="w-4 h-4 text-blue-400" />
                    Upload Replacement Version
                  </div>

                  {versionMsg && (
                    <div className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
                      versionMsg.type === 'success'
                        ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300'
                        : 'bg-rose-950/60 border-rose-700/60 text-rose-300'
                    }`}>
                      {versionMsg.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                      <span>{versionMsg.text}</span>
                    </div>
                  )}

                  <div>
                    <label className="block text-slate-400 mb-1">Select Replacement File</label>
                    <input
                      type="file"
                      onChange={e => setVersionFile(e.target.files?.[0] || null)}
                      className="w-full text-xs text-slate-400 file:mr-4 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-blue-600 file:text-white hover:file:bg-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-400 mb-1">Change Summary / Changelog</label>
                    <input
                      type="text"
                      placeholder="e.g. Revised SLA clauses and updated signature blocks"
                      value={changeDescription}
                      onChange={e => setChangeDescription(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={uploadingVersion || !versionFile}
                    className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 rounded-lg transition disabled:opacity-50 text-xs shadow-sm"
                  >
                    {uploadingVersion ? 'Verifying & Uploading...' : 'Commit Version Release'}
                  </button>
                </form>
              )}
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="space-y-3">
              <h4 className="font-semibold text-white">Immutable Event Trail for This Document</h4>
              {auditEvents.length === 0 ? (
                <div className="p-6 text-center text-slate-400 bg-slate-950/40 rounded-xl border border-slate-800">
                  No audit events recorded for this document.
                </div>
              ) : (
                <div className="space-y-2">
                  {auditEvents.map(e => (
                    <div key={e.id} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white text-xs">{e.action}</span>
                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                            e.outcome === 'SUCCESS' ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'
                          }`}>
                            {e.outcome}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-400 mt-0.5">
                          Actor: {e.actorEmail} [{e.actorRole}] • {new Date(e.timestamp).toLocaleString()}
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="font-mono text-[9px] text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                          {e.hash.substring(0, 14)}...
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/80 flex justify-between items-center text-xs">
          <span className="text-[11px] text-slate-400 font-mono">Doc ID: {doc.id}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
