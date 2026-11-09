/**
 * Enterprise Settings, Security Architecture & Deployment Guide
 * Displays zero-trust configurations, Firestore security rules, and infrastructure guides.
 */

import React, { useState } from 'react';
import {
  Shield,
  Lock,
  Database,
  Cloud,
  FileCode,
  Terminal,
  CheckCircle2,
  Copy,
  Check
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const sampleFirestoreRules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // DENY ALL DIRECT CLIENT-SIDE WRITES TO AUDIT AND GRANTS
    // All operations must pass through authenticated backend proxy!

    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow write: if false; // Admin backend only
    }

    match /documents/{documentId} {
      allow read: if false; // Mediated by backend authorization
      allow write: if false;
    }

    match /documentGrants/{grantId} {
      allow read, write: if false; // Strict zero client-side access
    }

    match /auditEvents/{eventId} {
      allow read, write: if false; // Immutable, append-only via server HMAC
    }

    match /auditCheckpoints/{checkpointId} {
      allow read, write: if false;
    }

    match /securityAlerts/{alertId} {
      allow read, write: if false;
    }
  }
}`;

  return (
    <div className="space-y-6 max-w-4xl text-xs text-slate-300">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight">Security Architecture & System Settings</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Zero-Trust specifications, cryptographic HMAC configuration, and production Cloud Run guidelines.
        </p>
      </div>

      {/* Security Posture Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold mb-1">
            <Lock className="w-4 h-4" />
            <span>IDOR Defense</span>
          </div>
          <div className="text-slate-200 font-bold text-sm">Strict 404 Anti-Recon</div>
          <p className="text-slate-400 text-[11px] mt-1 leading-snug">
            Unauthorized queries return 404 Not Found, preventing existence probing and horizontal escalation.
          </p>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center gap-2 text-blue-400 font-semibold mb-1">
            <Shield className="w-4 h-4" />
            <span>Audit Ledger</span>
          </div>
          <div className="text-slate-200 font-bold text-sm">HMAC-SHA256 Chained</div>
          <p className="text-slate-400 text-[11px] mt-1 leading-snug">
            Every security action forms an irreversible recursive hash link with backward pointer check.
          </p>
        </div>

        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center gap-2 text-indigo-400 font-semibold mb-1">
            <Database className="w-4 h-4" />
            <span>Object Vault</span>
          </div>
          <div className="text-slate-200 font-bold text-sm">UUID Key Isolation</div>
          <p className="text-slate-400 text-[11px] mt-1 leading-snug">
            Files stored outside web root with random tokens. Streamed through authenticated memory proxy.
          </p>
        </div>
      </div>

      {/* Firestore Security Rules Display */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-amber-400" />
            <h2 className="font-semibold text-white text-sm">Firestore Security Rules (Zero-Trust Model)</h2>
          </div>
          <button
            onClick={() => copyToClipboard(sampleFirestoreRules, 'rules')}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px]"
          >
            {copiedKey === 'rules' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedKey === 'rules' ? 'Copied' : 'Copy Rules'}
          </button>
        </div>
        <p className="text-slate-400 leading-relaxed">
          Clients are strictly prohibited from directly querying or mutating <code className="text-blue-300">auditEvents</code>, <code className="text-blue-300">documentGrants</code>, or <code className="text-blue-300">documents</code> via client-side SDKs. All requests must pass through backend verification endpoints.
        </p>
        <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
          {sampleFirestoreRules}
        </pre>
      </div>

      {/* Production Google Cloud Run & Cloud Storage Guide */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Cloud className="w-4 h-4 text-blue-400" />
          <h2 className="font-semibold text-white text-sm">Production Cloud Run & Private Storage Blueprint</h2>
        </div>

        <div className="space-y-3 text-slate-300 leading-relaxed">
          <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1.5">
            <div className="font-semibold text-white">1. Provision Private Google Cloud Storage Bucket</div>
            <p className="text-slate-400 text-[11px]">
              Create a private bucket with Uniform Bucket-Level Access and Public Access Prevention enabled:
            </p>
            <pre className="p-2.5 bg-slate-900 rounded font-mono text-[11px] text-emerald-300 overflow-x-auto">
              gcloud storage buckets create gs://trustvault-private-vault --uniform-bucket-level-access --location=asia-east1
            </pre>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1.5">
            <div className="font-semibold text-white">2. Least-Privilege Service Account Assignment</div>
            <p className="text-slate-400 text-[11px]">
              Bind <code className="text-blue-300">roles/storage.objectAdmin</code> to the Cloud Run service identity, strictly withholding public ACL permissions.
            </p>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1.5">
            <div className="font-semibold text-white">3. Environment Configuration</div>
            <p className="text-slate-400 text-[11px]">
              Inject the server-side audit HMAC secret and storage bucket name via Secret Manager:
            </p>
            <pre className="p-2.5 bg-slate-900 rounded font-mono text-[11px] text-blue-300 overflow-x-auto">
              AUDIT_HMAC_SECRET="[STRONG_64_CHAR_HEX_SECRET]"&#10;STORAGE_BUCKET_NAME="trustvault-private-vault"
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
