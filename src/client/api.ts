/**
 * TrustVault API Client
 * Secure typed HTTP client managing Bearer tokens and error envelopes
 */

import type {
  User,
  DocumentRecord,
  DocumentGrant,
  DocumentVersion,
  AuditEvent,
  SecurityAlert
} from '../server/types.js';

export interface AuthResponse {
  token: string;
  user: User;
  expiresAt: number;
}

export interface AdminMetrics {
  totalUsers: number;
  activeUsers: number;
  totalDocuments: number;
  activeDocuments: number;
  deletedDocuments: number;
  totalGrants: number;
  activeGrants: number;
  revokedGrants: number;
  totalDownloads: number;
  totalUploads: number;
  deniedAccessAttempts: number;
  auditChainStatus: string;
  totalAuditEvents: number;
}

export interface AdminDashboardData {
  metrics: AdminMetrics;
  categoryCounts: Record<string, number>;
  recentAlerts: SecurityAlert[];
  recentDeniedAttempts: AuditEvent[];
  recentActivity: AuditEvent[];
}

export interface VerificationResult {
  isValid: boolean;
  totalEvents: number;
  verifiedCount: number;
  corruptedEventId?: string;
  corruptedIndex?: number;
  reason?: string;
  lastVerifiedHash?: string;
}

export interface SecurityTestReport {
  totalTests: number;
  passed: number;
  failed: number;
  durationMs: number;
  mutationTestPassed: boolean;
  results: Array<{
    id: number;
    name: string;
    category: string;
    status: 'PASSED' | 'FAILED';
    description: string;
    evidence: string;
  }>;
}

class ApiService {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem('tv_auth_token');
  }

  public setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem('tv_auth_token', token);
    } else {
      localStorage.removeItem('tv_auth_token');
    }
  }

  public getToken(): string | null {
    return this.token;
  }

  private getHeaders(isJson = true): HeadersInit {
    const headers: Record<string, string> = {};
    if (isJson) {
      headers['Content-Type'] = 'application/json';
    }
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  private async handleResponse<T>(res: Response): Promise<T> {
    if (!res.ok) {
      let errorMsg = `HTTP Error ${res.status}`;
      try {
        const data = await res.json();
        errorMsg = data.message || data.error || errorMsg;
      } catch {}
      throw new Error(errorMsg);
    }
    return res.json() as Promise<T>;
  }

  // Auth
  public async login(email: string, password: string): Promise<AuthResponse> {
    const res = await fetch('/api/auth/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await this.handleResponse<AuthResponse>(res);
    this.setToken(data.token);
    return data;
  }

  public async logout(): Promise<void> {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: this.getHeaders()
      });
    } catch {}
    this.setToken(null);
  }

  public async getMe(): Promise<{ user: User }> {
    const res = await fetch('/api/auth/me', {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ user: User }>(res);
  }

  // Documents
  public async getDocuments(params?: { q?: string; category?: string; adminView?: boolean }): Promise<{ documents: DocumentRecord[] }> {
    const url = new URL('/api/documents', window.location.origin);
    if (params?.q) url.searchParams.set('q', params.q);
    if (params?.category) url.searchParams.set('category', params.category);
    if (params?.adminView) url.searchParams.set('adminView', 'true');

    const res = await fetch(url.toString(), {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ documents: DocumentRecord[] }>(res);
  }

  public async getDocument(id: string): Promise<{ document: DocumentRecord; userCanDownload: boolean }> {
    const res = await fetch(`/api/documents/${id}`, {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ document: DocumentRecord; userCanDownload: boolean }>(res);
  }

  public async uploadDocument(formData: FormData): Promise<{ document: DocumentRecord }> {
    const res = await fetch('/api/documents', {
      method: 'POST',
      headers: {
        Authorization: this.token ? `Bearer ${this.token}` : ''
      },
      body: formData
    });
    return this.handleResponse<{ document: DocumentRecord }>(res);
  }

  public async updateDocument(id: string, updates: Partial<DocumentRecord>): Promise<{ document: DocumentRecord }> {
    const res = await fetch(`/api/documents/${id}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    return this.handleResponse<{ document: DocumentRecord }>(res);
  }

  public async deleteDocument(id: string): Promise<{ success: boolean }> {
    const res = await fetch(`/api/documents/${id}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    return this.handleResponse<{ success: boolean }>(res);
  }

  public async restoreDocument(id: string): Promise<{ success: boolean }> {
    const res = await fetch(`/api/documents/${id}/restore`, {
      method: 'POST',
      headers: this.getHeaders()
    });
    return this.handleResponse<{ success: boolean }>(res);
  }

  public async getVersions(id: string): Promise<{ versions: DocumentVersion[] }> {
    const res = await fetch(`/api/documents/${id}/versions`, {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ versions: DocumentVersion[] }>(res);
  }

  public async uploadVersion(id: string, formData: FormData): Promise<{ version: DocumentVersion }> {
    const res = await fetch(`/api/documents/${id}/versions`, {
      method: 'POST',
      headers: {
        Authorization: this.token ? `Bearer ${this.token}` : ''
      },
      body: formData
    });
    return this.handleResponse<{ version: DocumentVersion }>(res);
  }

  public async downloadDocument(id: string, filename: string): Promise<void> {
    const res = await fetch(`/api/documents/${id}/download`, {
      headers: this.getHeaders(false)
    });

    if (!res.ok) {
      let errText = 'Failed to download document';
      try {
        const errJson = await res.json();
        errText = errJson.message || errText;
      } catch {}
      throw new Error(errText);
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  public async getPreviewUrl(id: string): Promise<string> {
    const res = await fetch(`/api/documents/${id}/preview`, {
      headers: this.getHeaders(false)
    });

    if (!res.ok) {
      let errText = 'Access denied for document preview.';
      try {
        const errJson = await res.json();
        errText = errJson.message || errText;
      } catch {}
      throw new Error(errText);
    }

    const blob = await res.blob();
    return window.URL.createObjectURL(blob);
  }

  // Permissions
  public async getPermissions(documentId: string): Promise<{ grants: DocumentGrant[] }> {
    const res = await fetch(`/api/documents/${documentId}/permissions`, {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ grants: DocumentGrant[] }>(res);
  }

  public async grantPermission(
    documentId: string,
    granteeEmail: string,
    permissionLevel: 'READ' | 'EDIT',
    expiresAt?: string | null
  ): Promise<{ grant: DocumentGrant }> {
    const res = await fetch(`/api/documents/${documentId}/permissions`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ granteeEmail, permissionLevel, expiresAt })
    });
    return this.handleResponse<{ grant: DocumentGrant }>(res);
  }

  public async revokePermission(documentId: string, grantId: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`/api/documents/${documentId}/permissions/${grantId}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    return this.handleResponse<{ success: boolean; message: string }>(res);
  }

  // Audit
  public async getAuditEvents(params?: {
    action?: string;
    outcome?: string;
    actorEmail?: string;
    limit?: number;
  }): Promise<{ events: AuditEvent[] }> {
    const url = new URL('/api/audit/events', window.location.origin);
    if (params?.action) url.searchParams.set('action', params.action);
    if (params?.outcome) url.searchParams.set('outcome', params.outcome);
    if (params?.actorEmail) url.searchParams.set('actorEmail', params.actorEmail);
    if (params?.limit) url.searchParams.set('limit', String(params.limit));

    const res = await fetch(url.toString(), {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ events: AuditEvent[] }>(res);
  }

  public async verifyAuditChain(): Promise<{ verification: VerificationResult }> {
    const res = await fetch('/api/audit/verify', {
      method: 'POST',
      headers: this.getHeaders()
    });
    return this.handleResponse<{ verification: VerificationResult }>(res);
  }

  // Admin
  public async getAdminDashboard(): Promise<AdminDashboardData> {
    const res = await fetch('/api/admin/dashboard', {
      headers: this.getHeaders()
    });
    return this.handleResponse<AdminDashboardData>(res);
  }

  // Users
  public async getUsers(): Promise<{ users: User[] }> {
    const res = await fetch('/api/users', {
      headers: this.getHeaders()
    });
    return this.handleResponse<{ users: User[] }>(res);
  }

  public async createUser(userData: {
    email: string;
    displayName: string;
    password: string;
    role: string;
  }): Promise<{ user: User }> {
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(userData)
    });
    return this.handleResponse<{ user: User }>(res);
  }

  public async updateUser(
    id: string,
    updates: { active?: boolean; role?: string; displayName?: string }
  ): Promise<{ user: User }> {
    const res = await fetch(`/api/users/${id}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    return this.handleResponse<{ user: User }>(res);
  }

  // Security Suite / Pentest
  public async runSecuritySuite(): Promise<{ report: SecurityTestReport }> {
    const res = await fetch('/api/security/run-tests', {
      method: 'POST',
      headers: this.getHeaders()
    });
    return this.handleResponse<{ report: SecurityTestReport }>(res);
  }
}

export const api = new ApiService();
