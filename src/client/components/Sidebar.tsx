/**
 * Enterprise Dark-Navy Sidebar
 * Role-aware navigation tailored for Administrator, Document Owner, and Viewer.
 */

import React from 'react';
import { useAuth } from '../context/AuthContext.js';
import {
  LayoutDashboard,
  FolderLock,
  UploadCloud,
  FileCheck2,
  ShieldAlert,
  Users,
  Settings,
  ShieldCheck,
  FileText
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'documents'
  | 'upload'
  | 'audit'
  | 'security-suite'
  | 'users'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const { user } = useAuth();
  if (!user) return null;

  const isAdmin = user.role === 'admin';
  const isOwner = user.role === 'owner';
  const isViewer = user.role === 'viewer';

  const navItems = [
    {
      id: 'dashboard' as NavTab,
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: user.role.toUpperCase(),
      visible: true
    },
    {
      id: 'documents' as NavTab,
      label: isViewer ? 'Shared With Me' : 'Document Vault',
      icon: FolderLock,
      visible: true
    },
    {
      id: 'upload' as NavTab,
      label: 'Upload Document',
      icon: UploadCloud,
      visible: isOwner || isAdmin
    },
    {
      id: 'audit' as NavTab,
      label: 'Audit Ledger',
      icon: FileCheck2,
      visible: true
    },
    {
      id: 'security-suite' as NavTab,
      label: 'Pentest & Security',
      icon: ShieldCheck,
      badge: '20 TESTS',
      visible: true
    },
    {
      id: 'users' as NavTab,
      label: 'User Directory',
      icon: Users,
      badge: 'ADMIN',
      visible: isAdmin
    },
    {
      id: 'settings' as NavTab,
      label: 'Settings & Specs',
      icon: Settings,
      visible: true
    }
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col justify-between shrink-0 select-none text-slate-300">
      <div className="p-4 space-y-6">
        {/* Navigation Section */}
        <div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-3 mb-2">
            Navigation Menu
          </div>
          <nav className="space-y-1">
            {navItems
              .filter(item => item.visible)
              .map(item => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectTab(item.id)}
                    className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-blue-600 text-white font-semibold shadow-lg shadow-blue-500/20'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/80'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                          isActive
                            ? 'bg-blue-800 text-blue-100'
                            : 'bg-slate-800 text-slate-300 border border-slate-700/60'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
          </nav>
        </div>

        {/* Security Policy Card */}
        <div className="p-3.5 rounded-xl bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800/80 text-xs">
          <div className="flex items-center gap-2 text-blue-400 font-semibold mb-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Zero-Trust Policy</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            {isViewer
              ? 'Viewers can only access documents explicitly shared with them. Downloading without active grant is blocked.'
              : isAdmin
              ? 'Admin role grants system audit access only. Admin cannot download confidential files without grant.'
              : 'Owners control document grants and immediate revocation. Deleted documents are held under retention.'}
          </p>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/50">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Private Vault Active
          </span>
          <span className="font-mono text-[10px] text-slate-400">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
};
