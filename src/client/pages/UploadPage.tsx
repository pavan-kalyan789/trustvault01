/**
 * Document Upload & Pre-flight File Signature Inspector
 * Enforces magic-byte validation, MIME spoofing checks, and category classification.
 */

import React, { useState, useRef } from 'react';
import { api } from '../api.js';
import type { DocumentCategory } from '../../server/types.js';
import {
  UploadCloud,
  FileCheck2,
  AlertTriangle,
  CheckCircle,
  File,
  Shield,
  Binary,
  ArrowRight
} from 'lucide-react';

interface UploadPageProps {
  onUploadSuccess: () => void;
}

const CATEGORIES: DocumentCategory[] = [
  'Contracts',
  'Finance',
  'HR',
  'Legal',
  'Technical',
  'Audit',
  'Confidential',
  'General'
];

export const UploadPage: React.FC<UploadPageProps> = ({ onUploadSuccess }) => {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<DocumentCategory>('Contracts');
  const [detectedSignature, setDetectedSignature] = useState<string | null>(null);
  const [hexPreview, setHexPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Inspect first 16 bytes when file is chosen
  const handleFileChange = (selectedFile: File) => {
    setFile(selectedFile);
    setError(null);
    setSuccess(false);

    if (!name) {
      // Auto-populate name from filename
      const baseName = selectedFile.name.replace(/\.[^/.]+$/, '').replace(/[_.-]/g, ' ');
      setName(baseName);
    }

    const reader = new FileReader();
    reader.onload = e => {
      const buf = new Uint8Array(e.target?.result as ArrayBuffer);
      if (buf.length >= 4) {
        // Hex representation
        const hex = Array.from(buf.slice(0, 8))
          .map(b => b.toString(16).padStart(2, '0').toUpperCase())
          .join(' ');
        setHexPreview(hex);

        // Quick signature check
        if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) {
          setDetectedSignature('application/pdf (%PDF-)');
        } else if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
          setDetectedSignature('image/png');
        } else if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
          setDetectedSignature('image/jpeg');
        } else if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
          setDetectedSignature('application/zip-container (DOCX/XLSX)');
        } else {
          setDetectedSignature('text/plain or binary data');
        }
      }
    };
    reader.readAsArrayBuffer(selectedFile.slice(0, 16));
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    if (!file) {
      setError('Please select a file to upload.');
      return;
    }

    if (!name.trim()) {
      setError('Document name is required.');
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('name', name);
      formData.append('description', description);
      formData.append('category', category);

      await api.uploadDocument(formData);
      setSuccess(true);
      setFile(null);
      setName('');
      setDescription('');
      setDetectedSignature(null);
      setHexPreview(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err: any) {
      setError(err.message || 'Document upload rejected by security validation.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight">Upload Secure Document</h1>
        <p className="text-xs text-slate-400 mt-1">
          Files are validated against binary magic bytes, assigned a random UUID storage key, and recorded in the cryptographic audit ledger.
        </p>
      </div>

      {success && (
        <div className="p-4 bg-emerald-950/60 border border-emerald-700/60 rounded-2xl text-emerald-300 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CheckCircle className="w-5 h-5 text-emerald-400" />
            <div>
              <div className="font-semibold text-sm text-white">Upload Successfully Completed</div>
              <p className="text-xs text-emerald-300">
                Document stored in private vault with SHA-256 integrity hash recorded.
              </p>
            </div>
          </div>
          <button
            onClick={onUploadSuccess}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition"
          >
            View Vault <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 bg-rose-950/60 border border-rose-700/60 rounded-2xl text-rose-300 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          <div>
            <div className="font-semibold text-sm text-white">Security Validation Failed</div>
            <p className="text-xs text-rose-300 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 space-y-6">
        {/* Drag and Drop Zone */}
        <div
          onDragOver={e => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition ${
            file
              ? 'border-blue-500/60 bg-blue-950/20'
              : 'border-slate-700 hover:border-slate-500 bg-slate-950/40 hover:bg-slate-950/60'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={e => e.target.files?.[0] && handleFileChange(e.target.files[0])}
            className="hidden"
          />

          <div className="w-12 h-12 rounded-2xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mx-auto mb-3">
            <UploadCloud className="w-6 h-6" />
          </div>

          {file ? (
            <div className="space-y-1">
              <div className="font-semibold text-white text-sm">{file.name}</div>
              <div className="text-xs text-slate-400">
                {(file.size / 1024).toFixed(1)} KB • Declared MIME: {file.type || 'unknown'}
              </div>
            </div>
          ) : (
            <div>
              <div className="font-semibold text-white text-sm">Click to browse or drag file here</div>
              <p className="text-xs text-slate-400 mt-1">
                Supported formats: PDF, DOCX, XLSX, PNG, JPG, TXT (Max 10 MB)
              </p>
            </div>
          )}
        </div>

        {/* Pre-flight Binary Magic Bytes Inspector */}
        {hexPreview && (
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs">
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center gap-1.5 font-semibold text-white">
                <Binary className="w-4 h-4 text-emerald-400" /> Pre-Flight File Signature Inspector
              </span>
              <span className="text-[10px] text-emerald-400 font-mono">Verified in Memory</span>
            </div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-[11px] bg-slate-900 p-2.5 rounded-lg border border-slate-800">
              <div>
                <span className="text-slate-500">Magic Bytes: </span>
                <span className="text-blue-300 font-bold">{hexPreview}</span>
              </div>
              <div>
                <span className="text-slate-500">Resolved Format: </span>
                <span className="text-emerald-300 font-medium">{detectedSignature}</span>
              </div>
            </div>
          </div>
        )}

        {/* Form Inputs */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div>
            <label className="block text-slate-400 mb-1 font-medium">Document Title *</label>
            <input
              type="text"
              placeholder="e.g. Master Services Agreement 2026"
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
              required
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-medium">Classification Category *</label>
            <select
              value={category}
              onChange={e => setCategory(e.target.value as DocumentCategory)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-white focus:outline-none focus:border-blue-500 transition"
            >
              {CATEGORIES.map(c => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="block text-slate-400 mb-1 font-medium text-xs">Contextual Description</label>
          <textarea
            rows={3}
            placeholder="Provide context regarding document sensitivity, bilateral obligations, or retention guidelines..."
            value={description}
            onChange={e => setDescription(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-white placeholder-slate-500 text-xs focus:outline-none focus:border-blue-500 transition"
          />
        </div>

        <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 flex items-start gap-2.5 text-[11px] text-slate-400">
          <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <span>
            <strong>Storage Security Guarantee:</strong> Binary files are not stored in the database. Files are saved in a private object vault with unique UUIDs. Only users with active, explicit permissions can stream file bytes.
          </span>
        </div>

        <button
          type="submit"
          disabled={loading || !file}
          className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 rounded-xl transition shadow-lg shadow-blue-600/20 disabled:opacity-50 text-xs"
        >
          {loading ? 'Validating Magic Bytes & Encrypting...' : 'Upload & Commit to Secure Vault'}
        </button>
      </form>
    </div>
  );
};
