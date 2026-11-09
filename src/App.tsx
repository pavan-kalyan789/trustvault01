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
import { LoginPage } from './client/pages/LoginPage.js';
import { ShareModal } from './client/components/ShareModal.js';
import { DocumentDetailsModal } from './client/components/DocumentDetailsModal.js';
import { AuditVerifyModal } from './client/components/AuditVerifyModal.js';
import type { DocumentRecord } from './server/types.js';

const MainLayout: React.FC = () => {
  const { user, loading } = useAuth();
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [selectedDocForDetails, setSelectedDocForDetails] = useState<DocumentRecord | null>(null);
  const [selectedDocForShare, setSelectedDocForShare] = useState<DocumentRecord | null>(null);
  const [showVerifyModal, setShowVerifyModal] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400">
        <div className="text-center space-y-3">
          <div className="w-10 h-10 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="font-semibold text-white text-sm">Initializing Secure Vault...</div>
          <p className="text-xs text-slate-500">Checking hardware session tokens and cryptographic chain</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
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
            {currentTab === 'dashboard' && (
              <>
                {user.role === 'admin' ? (
                  <AdminDashboard
                    onNavigateToPentest={() => setCurrentTab('security-suite')}
                    onNavigateToAudit={() => setCurrentTab('audit')}
                  />
                ) : user.role === 'owner' ? (
                  <OwnerDashboard
                    onOpenUpload={() => setCurrentTab('upload')}
                    onSelectDocument={doc => setSelectedDocForDetails(doc)}
                    onShareDocument={doc => setSelectedDocForShare(doc)}
                  />
                ) : (
                  <ViewerDashboard
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
