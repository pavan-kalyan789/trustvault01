/**
 * Document Library
 * Table & Grid views, category filters, instant search, and permission actions.
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api.js';
import { useAuth } from '../context/AuthContext.js';
import type { DocumentRecord, DocumentCategory } from '../../server/types.js';
import {
  Search,
  Filter,
  LayoutGrid,
  List,
  Upload,
  Download,
  Share2,
  Eye,
  Trash2,
  FileText,
  Shield,
  Lock
} from 'lucide-react';

interface DocumentLibraryPageProps {
  onOpenUpload: () => void;
  onSelectDocument: (doc: DocumentRecord) => void;
  onShareDocument: (doc: DocumentRecord) => void;
}

const CATEGORIES = [
  'ALL',
  'Contracts',
  'Finance',
  'HR',
  'Legal',
  'Technical',
  'Audit',
  'Confidential',
  'General'
];

export const DocumentLibraryPage: React.FC<DocumentLibraryPageProps> = ({
  onOpenUpload,
  onSelectDocument,
  onShareDocument
}) => {
  const { user } = useAuth();
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [viewMode, setViewMode] = useState<'table' | 'grid'>('table');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const fetchDocs = async () => {
    try {
      setLoading(true);
      const res = await api.getDocuments({
        q: searchQuery,
        category: selectedCategory === 'ALL' ? undefined : selectedCategory,
        adminView: user?.role === 'admin'
      });
      setDocuments(res.documents);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchDocs();
    }, 200);
    return () => clearTimeout(timer);
  }, [searchQuery, selectedCategory]);

  const handleDownload = async (doc: DocumentRecord) => {
    setDownloadingId(doc.id);
    try {
      await api.downloadDocument(doc.id, doc.originalFilename);
    } catch (err: any) {
      alert(`Download Error: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (doc: DocumentRecord) => {
    if (!confirm(`Are you sure you want to soft-delete '${doc.name}'?`)) return;
    try {
      await api.deleteDocument(doc.id);
      await fetchDocs();
    } catch (err: any) {
      alert(`Delete Error: ${err.message}`);
    }
  };

  const isOwner = (doc: DocumentRecord) => user?.id === doc.ownerId;
  const canUpload = user?.role === 'owner' || user?.role === 'admin';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Enterprise Document Vault</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographically verified files with continuous authorization enforcement.
          </p>
        </div>

        {canUpload && (
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition shadow-lg shadow-blue-600/20"
          >
            <Upload className="w-4 h-4" /> Upload Document
          </button>
        )}
      </div>

      {/* Search and Category Filter Toolbar */}
      <div className="bg-slate-900/90 p-4 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative w-full sm:w-96">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by name, description, or filename..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
            />
          </div>

          {/* View Mode Toggle */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setViewMode('table')}
              className={`p-1.5 rounded-lg transition ${
                viewMode === 'table' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
              title="Table View"
            >
              <List className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('grid')}
              className={`p-1.5 rounded-lg transition ${
                viewMode === 'grid' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
              title="Grid View"
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Category Filter Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          <span className="text-[11px] font-semibold text-slate-500 uppercase mr-1">Categories:</span>
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1 rounded-lg font-medium transition text-xs shrink-0 ${
                selectedCategory === cat
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Documents Display */}
      {loading ? (
        <div className="py-24 text-center text-slate-400 text-xs">
          <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-3"></div>
          Scanning vault database...
        </div>
      ) : documents.length === 0 ? (
        <div className="py-16 text-center text-slate-400 bg-slate-900/60 rounded-2xl border border-slate-800 p-8 space-y-2">
          <Lock className="w-10 h-10 text-slate-600 mx-auto" />
          <div className="font-semibold text-white text-sm">No Matching Documents Found</div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Either no documents match the active search filters, or your account lacks explicit authorization.
          </p>
        </div>
      ) : viewMode === 'table' ? (
        /* Table View */
        <div className="bg-slate-900/90 rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/80 text-slate-400 font-semibold border-b border-slate-800 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-3.5 px-4">Document Name</th>
                  <th className="py-3.5 px-4">Category</th>
                  <th className="py-3.5 px-4">Owner</th>
                  <th className="py-3.5 px-4">Size & Version</th>
                  <th className="py-3.5 px-4">SHA-256 Hash</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {documents.map(doc => (
                  <tr key={doc.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                          <FileText className="w-4 h-4" />
                        </div>
                        <div>
                          <span
                            onClick={() => onSelectDocument(doc)}
                            className="font-semibold text-white hover:text-blue-400 cursor-pointer block"
                          >
                            {doc.name}
                          </span>
                          <span className="text-[11px] text-slate-400 font-mono truncate max-w-xs block">
                            {doc.originalFilename}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
                        {doc.category}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                      {doc.ownerEmail}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-blue-900/60 text-blue-300 border border-blue-700/60">
                          v{doc.version}
                        </span>
                        <span className="text-slate-400">{(doc.size / 1024).toFixed(1)} KB</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono text-[10px] text-emerald-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                        {doc.sha256Hash.substring(0, 12)}...
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleDownload(doc)}
                          disabled={downloadingId === doc.id}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                          title="Authorized Download"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>
                        {isOwner(doc) && (
                          <button
                            onClick={() => onShareDocument(doc)}
                            className="p-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition"
                            title="Manage Permissions"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                        <button
                          onClick={() => onSelectDocument(doc)}
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                          title="Details & Audit"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        {isOwner(doc) && (
                          <button
                            onClick={() => handleDelete(doc)}
                            className="p-1.5 rounded-lg text-rose-400 hover:text-white hover:bg-rose-600/30 transition border border-rose-800/40"
                            title="Soft-Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Grid View */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {documents.map(doc => (
            <div
              key={doc.id}
              className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-4 hover:border-slate-700 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {doc.category}
                  </span>
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/60">
                    Release v{doc.version}
                  </span>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div>
                    <h3
                      onClick={() => onSelectDocument(doc)}
                      className="font-semibold text-white text-sm hover:text-blue-400 cursor-pointer line-clamp-1"
                    >
                      {doc.name}
                    </h3>
                    <p className="text-[11px] text-slate-400 font-mono truncate max-w-[200px]">
                      {doc.originalFilename}
                    </p>
                  </div>
                </div>

                <p className="text-xs text-slate-400 mt-3 line-clamp-2 leading-relaxed">
                  {doc.description || 'Enterprise restricted document.'}
                </p>
              </div>

              <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-[11px] text-slate-400">{(doc.size / 1024).toFixed(1)} KB</span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleDownload(doc)}
                    disabled={downloadingId === doc.id}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                    title="Download"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                  {isOwner(doc) && (
                    <button
                      onClick={() => onShareDocument(doc)}
                      className="p-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30"
                      title="Share"
                    >
                      <Share2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                  <button
                    onClick={() => onSelectDocument(doc)}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                    title="View details"
                  >
                    <Eye className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
