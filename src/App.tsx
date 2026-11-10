/**
 * TrustVault - Main Application Entry
 * Enterprise Secure Document Sharing Platform with Cryptographic Audit Trail
 */

import React, { useState } from 'react';
import { AuthProvider, useAuth } from './client/context/AuthContext.js';
import { Navbar } from './client/components/Navbar.js';
import { Sidebar, type NavTab } from './client/components/Sidebar.js';
import { AdminDashboard } from './client/pages/AdminDashboard.js';
import { OwnerDashboard } from './client/pages/OwnerDashboard.js';
import { ViewerDashboard } from './client/pages/ViewerDashboard.js';
import { DocumentLibraryPage } from './client/pages/DocumentLibraryPage.js';
import { UploadPage } from './client/pages/UploadPage.js';
import { AuditTrailPage } from './client/pages/AuditTrailPage.js';
import { PentestConsolePage } from './client/pages/PentestConsolePage.js';
import { UserManagementPage } from './client/pages/UserManagementPage.js';
import { SettingsPage } from './client/pages/SettingsPage.js';
import { ShareModal } from './client/components/ShareModal.js';
import { DocumentDetailsModal } from './client/components/DocumentDetailsModal.js';
import { AuditVerifyModal } from './client/components/AuditVerifyModal.js';
import { Shield, UserCheck, Lock } from 'lucide-react';
import type { DocumentRecord } from './server/types.js';

const MainLayout: React.FC = () => {
  const { user, loading, switchDemoAccount } = useAuth();
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [selectedDocForDetails, setSelectedDocForDetails] = useState<DocumentRecord | null>(null);
  const [selectedDocForShare, setSelectedDocForShare] = useState<DocumentRecord | null>(null);
  const [showVerifyModal, setShowVerifyModal] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400">
        <div className="text-center space-y-3">
          <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="font-semibold text-white text-sm">Entering TrustVault...</div>
          <p className="text-xs text-slate-500">Connecting to secure JSON database and verified credentials</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col text-slate-100">
      <Navbar
        onOpenAuditVerify={() => setShowVerifyModal(true)}
        onOpenPentest={() => setCurrentTab('security-suite')}
      />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />

        <main className="flex-1 overflow-y-auto bg-slate-950 p-6 md:p-8">
          <div className="max-w-7xl mx-auto">
            {/* If not logged in, show instant switch login home banner */}
            {!user && (
              <div className="p-8 rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800 shadow-2xl mb-8 space-y-6 text-center">
                <div className="max-w-xl mx-auto space-y-3">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold">
                    <UserCheck className="w-3.5 h-3.5" /> Instant Role Switching • No Credentials Required
                  </div>
                  <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                    Welcome to TrustVault
                  </h1>
                  <p className="text-sm text-slate-400">
                    Select a verified profile to enter the vault. Switch roles at any time from the top bar to inspect permissions, audit chains, and document isolation.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 max-w-4xl mx-auto pt-2">
                  <button
                    onClick={() => switchDemoAccount('owner')}
                    className="p-5 rounded-2xl bg-slate-950/80 border border-emerald-500/30 hover:border-emerald-500/70 hover:bg-emerald-950/20 transition-all text-left space-y-2 group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">Owner (Default)</span>
                      <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                    </div>
                    <div className="font-bold text-white text-base group-hover:text-emerald-300 transition">Sarah Chen</div>
                    <div className="text-[11px] text-slate-400 font-mono">owner@trustvault.local</div>
                    <p className="text-[11px] text-slate-400 pt-1 leading-snug">Full rights, upload documents, grant and immediately revoke access.</p>
                  </button>

                  <button
                    onClick={() => switchDemoAccount('admin')}
                    className="p-5 rounded-2xl bg-slate-950/80 border border-rose-500/30 hover:border-rose-500/70 hover:bg-rose-950/20 transition-all text-left space-y-2 group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-rose-400">Administrator</span>
                      <span className="w-2 h-2 rounded-full bg-rose-400"></span>
                    </div>
                    <div className="font-bold text-white text-base group-hover:text-rose-300 transition">Chief Security Officer</div>
                    <div className="text-[11px] text-slate-400 font-mono">admin@trustvault.local</div>
                    <p className="text-[11px] text-slate-400 pt-1 leading-snug">Governance overview, security telemetry, user accounts, and JSON DB export.</p>
                  </button>

                  <button
                    onClick={() => switchDemoAccount('viewer')}
                    className="p-5 rounded-2xl bg-slate-950/80 border border-blue-500/30 hover:border-blue-500/70 hover:bg-blue-950/20 transition-all text-left space-y-2 group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-blue-400">Compliance Auditor</span>
                      <span className="w-2 h-2 rounded-full bg-blue-400"></span>
                    </div>
                    <div className="font-bold text-white text-base group-hover:text-blue-300 transition">Marcus Vance</div>
                    <div className="text-[11px] text-slate-400 font-mono">viewer@trustvault.local</div>
                    <p className="text-[11px] text-slate-400 pt-1 leading-snug">Read-only granted documents, verify HMAC audit chain integrity.</p>
                  </button>

                  <button
                    onClick={() => switchDemoAccount('other')}
                    className="p-5 rounded-2xl bg-slate-950/80 border border-amber-500/30 hover:border-amber-500/70 hover:bg-amber-950/20 transition-all text-left space-y-2 group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-amber-400">External Contractor</span>
                      <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                    </div>
                    <div className="font-bold text-white text-base group-hover:text-amber-300 transition">Alex Morgan</div>
                    <div className="text-[11px] text-slate-400 font-mono">other@trustvault.local</div>
                    <p className="text-[11px] text-slate-400 pt-1 leading-snug">Demonstrates IDOR denial and 404 anti-recon on unshared documents.</p>
                  </button>
                </div>
              </div>
            )}

            {currentTab === 'dashboard' && user && (
              <>
                {user.role === 'admin' ? (
                  <AdminDashboard
                    key={`admin-${user.id}`}
                    onNavigateToPentest={() => setCurrentTab('security-suite')}
                    onNavigateToAudit={() => setCurrentTab('audit')}
                  />
                ) : user.role === 'owner' ? (
                  <OwnerDashboard
                    key={`owner-${user.id}`}
                    onOpenUpload={() => setCurrentTab('upload')}
                    onSelectDocument={doc => setSelectedDocForDetails(doc)}
                    onShareDocument={doc => setSelectedDocForShare(doc)}
                  />
                ) : (
                  <ViewerDashboard
                    key={`viewer-${user.id}`}
                    onSelectDocument={doc => setSelectedDocForDetails(doc)}
                  />
                )}
              </>
            )}

            {currentTab === 'documents' && (
              <DocumentLibraryPage
                onOpenUpload={() => setCurrentTab('upload')}
                onSelectDocument={doc => setSelectedDocForDetails(doc)}
                onShareDocument={doc => setSelectedDocForShare(doc)}
              />
            )}

            {currentTab === 'upload' && (
              <UploadPage onUploadSuccess={() => setCurrentTab('documents')} />
            )}

            {currentTab === 'audit' && (
              <AuditTrailPage onOpenVerifyModal={() => setShowVerifyModal(true)} />
            )}

            {currentTab === 'security-suite' && <PentestConsolePage />}

            {currentTab === 'users' && <UserManagementPage />}

            {currentTab === 'settings' && <SettingsPage />}
          </div>
        </main>
      </div>

      {/* Share Modal */}
      {selectedDocForShare && (
        <ShareModal
          document={selectedDocForShare}
          onClose={() => setSelectedDocForShare(null)}
          onGrantUpdated={() => {}}
        />
      )}

      {/* Details & Preview Modal */}
      {selectedDocForDetails && (
        <DocumentDetailsModal
          document={selectedDocForDetails}
          onClose={() => setSelectedDocForDetails(null)}
          onDocumentUpdated={() => {}}
          onOpenShare={() => {
            const doc = selectedDocForDetails;
            setSelectedDocForDetails(null);
            setSelectedDocForShare(doc);
          }}
        />
      )}

      {/* Cryptographic Audit Verify Modal */}
      {showVerifyModal && (
        <AuditVerifyModal onClose={() => setShowVerifyModal(false)} />
      )}
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
}
