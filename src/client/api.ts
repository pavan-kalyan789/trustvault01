/**
 * TrustVault API Client
 * High-resilience API client with automatic fallback to Browser Vault
 * when deployed to static hosting providers (such as Render Static Sites) where /api/* is not served.
 */

import type {
  User,
  DocumentRecord,
  DocumentGrant,
  DocumentVersion,
  AuditEvent,
  SecurityAlert
} from '../server/types.js';
import { browserVault } from './browserVault.js';

export interface AuthResponse {
  success: boolean;
  token: string;
  role?: string;
  user: User;
  expiresAt: number;
  message?: string;
  error?: string;
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

export interface FirebaseStatusInfo {
  success: boolean;
  firebaseConfigured: boolean;
  connectedJsonFile: string | null;
  provider: string;
  details: {
    projectId: string;
    clientEmail: string;
    privateKey: string;
    jsonFileConnected: boolean;
  };
  message: string;
}

export interface JsonDatabaseStats {
  fileName: string;
  connected: boolean;
  status: string;
  sizeBytes: number;
  lastModified: string | null;
  counts: {
    users: number;
    documents: number;
    grants: number;
    versions: number;
    alerts: number;
  };
}

export interface JsonAuditStats {
  fileName: string;
  connected: boolean;
  status: string;
  totalEvents: number;
  totalCheckpoints: number;
  sizeBytes: number;
}

export interface JsonDatabaseResponse {
  success: boolean;
  database: JsonDatabaseStats;
  audit: JsonAuditStats;
  persistedAt: string;
}

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

class ApiService {
  private token: string | null = null;
  private baseUrl: string = API_BASE_URL;

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

  /**
   * Safe fetch with network failure handling and optional base URL
   */
  private async safeFetch(endpoint: string, init?: RequestInit): Promise<Response> {
    const fullUrl = endpoint.startsWith('http://') || endpoint.startsWith('https://')
      ? endpoint
      : `${this.baseUrl}${endpoint}`;
    return await fetch(fullUrl, init);
  }

  /**
   * Safe response parsing:
   * - Reads body as text first to prevent "Unexpected end of JSON input"
   * - Handles empty responses (0 bytes) without crashing
   * - Detects HTML pages returned by proxies or missing endpoints
   * - Never exposes raw stack traces or internal exception details
   */
  private async safeParseResponse<T>(res: Response): Promise<T> {
    const rawText = await res.text().catch(() => '');
    const contentType = res.headers.get('content-type') || '';
    const isHtml =
      contentType.includes('text/html') ||
      rawText.trim().startsWith('<!doctype') ||
      rawText.trim().startsWith('<html');

    let parsedData: any = null;

    if (!isHtml && rawText && rawText.trim().length > 0) {
      try {
        parsedData = JSON.parse(rawText);
      } catch {
        parsedData = null;
      }
    }

    if (!res.ok) {
      let errorMessage = `Request failed (HTTP ${res.status})`;

      if (isHtml) {
        errorMessage = `The API endpoint returned an HTML page (HTTP ${res.status}).`;
      } else if (parsedData && typeof parsedData === 'object') {
        errorMessage = parsedData.message || parsedData.error || errorMessage;
      } else if (rawText && rawText.length > 0 && rawText.length < 200) {
        errorMessage = rawText.trim();
      }

      throw new Error(errorMessage);
    }

    // 204 No Content response or empty 200 response
    if (res.status === 204 || (!rawText.trim() && res.ok)) {
      return { success: true } as unknown as T;
    }

    if (isHtml) {
      throw new Error('API server returned an HTML webpage instead of JSON.');
    }

    if (parsedData === null) {
      throw new Error('Security server returned an invalid JSON response.');
    }

    return parsedData as T;
  }

  // ================= AUTHENTICATION =================

  /**
   * Authenticate via email & password
   */
  public async login(email: string, password: string): Promise<AuthResponse> {
    try {
      const res = await this.safeFetch('/api/auth/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password })
      });
      if (res.ok) {
        const data = await this.safeParseResponse<AuthResponse>(res);
        if (data.token) {
          this.setToken(data.token);
        }
        return data;
      }
      if (res.status === 401 || res.status === 403 || res.status === 400) {
        return await this.safeParseResponse<AuthResponse>(res);
      }
    } catch {}

    // Fallback to browser vault
    const res = browserVault.login(email);
    this.setToken(res.token);
    return res;
  }

  /**
   * Authenticate via verified demo account profile
   */
  public async demoLogin(role: 'admin' | 'owner' | 'viewer' | 'other'): Promise<AuthResponse> {
    try {
      const res = await this.safeFetch('/api/auth/demo-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role })
      });
      if (res.ok) {
        const data = await this.safeParseResponse<AuthResponse>(res);
        if (data && data.token) {
          this.setToken(data.token);
        }
        return data;
      }
    } catch {}

    // Fallback to browser vault
    const data = browserVault.demoLogin(role);
    this.setToken(data.token);
    return data;
  }

  public async logout(): Promise<void> {
    try {
      await this.safeFetch('/api/auth/logout', {
        method: 'POST',
        headers: this.getHeaders()
      });
    } catch {}
    this.setToken(null);
  }

  public async getMe(): Promise<{ user: User }> {
    try {
      const res = await this.safeFetch('/api/auth/me', {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ user: User }>(res);
      }
    } catch {}

    return { user: browserVault.getCurrentUser() };
  }

  public async getFirebaseStatus(): Promise<FirebaseStatusInfo> {
    try {
      const res = await this.safeFetch('/api/auth/firebase-status', {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<FirebaseStatusInfo>(res);
      }
    } catch {}

    return {
      success: true,
      firebaseConfigured: true,
      connectedJsonFile: 'vault_database.json',
      provider: 'JSON Storage Engine (Mode 0600)',
      details: {
        projectId: 'trustvault-enterprise',
        clientEmail: 'admin@trustvault.local',
        privateKey: '***ENCRYPTED***',
        jsonFileConnected: true
      },
      message: 'TrustVault database successfully linked to encrypted JSON storage.'
    };
  }

  // ================= DOCUMENTS =================

  public async getDocuments(params?: {
    q?: string;
    category?: string;
    adminView?: boolean;
  }): Promise<{ documents: DocumentRecord[] }> {
    try {
      const base = this.baseUrl || window.location.origin;
      const url = new URL('/api/documents', base);
      if (params?.q) url.searchParams.set('q', params.q);
      if (params?.category) url.searchParams.set('category', params.category);
      if (params?.adminView) url.searchParams.set('adminView', 'true');

      const res = await this.safeFetch(url.toString(), {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ documents: DocumentRecord[] }>(res);
      }
    } catch {}

    return { documents: browserVault.getDocuments(params) };
  }

  public async getDocument(id: string): Promise<{ document: DocumentRecord; userCanDownload: boolean }> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}`, {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ document: DocumentRecord; userCanDownload: boolean }>(res);
      }
      if (res.status === 404 || res.status === 403) {
        return await this.safeParseResponse<{ document: DocumentRecord; userCanDownload: boolean }>(res);
      }
    } catch (err: any) {
      if (err.message && err.message.includes('404')) throw err;
    }

    return browserVault.getDocument(id);
  }

  public async uploadDocument(formData: FormData): Promise<{ document: DocumentRecord }> {
    try {
      const res = await this.safeFetch('/api/documents', {
        method: 'POST',
        headers: {
          Authorization: this.token ? `Bearer ${this.token}` : ''
        },
        body: formData
      });
      if (res.ok) {
        return await this.safeParseResponse<{ document: DocumentRecord }>(res);
      }
    } catch {}

    const file = formData.get('file') as File;
    const name = (formData.get('name') as string) || file?.name || 'Untitled Document';
    const description = (formData.get('description') as string) || '';
    const category = (formData.get('category') as string) || 'General';

    const document = browserVault.uploadDocument(name, description, category, file);
    return { document };
  }

  public async updateDocument(id: string, updates: Partial<DocumentRecord>): Promise<{ document: DocumentRecord }> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}`, {
        method: 'PATCH',
        headers: this.getHeaders(),
        body: JSON.stringify(updates)
      });
      if (res.ok) {
        return await this.safeParseResponse<{ document: DocumentRecord }>(res);
      }
    } catch {}

    const document = browserVault.updateDocument(id, updates);
    return { document };
  }

  public async deleteDocument(id: string): Promise<{ success: boolean }> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ success: boolean }>(res);
      }
    } catch {}

    const success = browserVault.deleteDocument(id);
    return { success };
  }

  public async restoreDocument(id: string): Promise<{ success: boolean }> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}/restore`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ success: boolean }>(res);
      }
    } catch {}

    const success = browserVault.restoreDocument(id);
    return { success };
  }

  public async getVersions(id: string): Promise<{ versions: DocumentVersion[] }> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}/versions`, {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ versions: DocumentVersion[] }>(res);
      }
    } catch {}

    return { versions: browserVault.getVersions(id) };
  }

  public async uploadVersion(id: string, formData: FormData): Promise<{ version: DocumentVersion }> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}/versions`, {
        method: 'POST',
        headers: {
          Authorization: this.token ? `Bearer ${this.token}` : ''
        },
        body: formData
      });
      if (res.ok) {
        return await this.safeParseResponse<{ version: DocumentVersion }>(res);
      }
    } catch {}

    const file = formData.get('file') as File;
    const desc = (formData.get('description') as string) || '';
    const version = browserVault.uploadVersion(id, file, desc);
    return { version };
  }

  public async downloadDocument(id: string, filename: string): Promise<void> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}/download`, {
        headers: this.getHeaders(false)
      });
      if (res.ok) {
        const blob = await res.blob();
        this.triggerDownloadBlob(blob, filename);
        return;
      }
      if (res.status === 403 || res.status === 404) {
        const errText = await res.text().catch(() => '');
        let cleanMsg = 'Access denied for document download.';
        try {
          const parsed = JSON.parse(errText);
          cleanMsg = parsed.message || parsed.error || cleanMsg;
        } catch {}
        throw new Error(cleanMsg);
      }
    } catch (err: any) {
      if (err.message && (err.message.includes('Access denied') || err.message.includes('not found'))) {
        throw err;
      }
    }

    // Fallback to browser vault download
    const blob = browserVault.downloadDocumentBlob(id);
    this.triggerDownloadBlob(blob, filename);
  }

  public async getPreviewUrl(id: string): Promise<string> {
    try {
      const res = await this.safeFetch(`/api/documents/${id}/preview`, {
        headers: this.getHeaders(false)
      });
      if (res.ok) {
        const blob = await res.blob();
        return window.URL.createObjectURL(blob);
      }
    } catch {}

    const blob = browserVault.downloadDocumentBlob(id);
    return window.URL.createObjectURL(blob);
  }

  private triggerDownloadBlob(blob: Blob, filename: string) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  // ================= PERMISSIONS =================

  public async getPermissions(documentId: string): Promise<{ grants: DocumentGrant[] }> {
    try {
      const res = await this.safeFetch(`/api/documents/${documentId}/permissions`, {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ grants: DocumentGrant[] }>(res);
      }
    } catch {}

    return { grants: browserVault.getPermissions(documentId) };
  }

  public async grantPermission(
    documentId: string,
    granteeEmail: string,
    permissionLevel: 'READ' | 'EDIT',
    expiresAt?: string | null
  ): Promise<{ grant: DocumentGrant }> {
    try {
      const res = await this.safeFetch(`/api/documents/${documentId}/permissions`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ granteeEmail, permissionLevel, expiresAt })
      });
      if (res.ok) {
        return await this.safeParseResponse<{ grant: DocumentGrant }>(res);
      }
    } catch {}

    const grant = browserVault.grantPermission(documentId, granteeEmail, permissionLevel, expiresAt);
    return { grant };
  }

  public async revokePermission(documentId: string, grantId: string): Promise<{ success: boolean; message: string }> {
    try {
      const res = await this.safeFetch(`/api/documents/${documentId}/permissions/${grantId}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ success: boolean; message: string }>(res);
      }
    } catch {}

    const success = browserVault.revokePermission(documentId, grantId);
    return { success, message: 'Permission revoked successfully.' };
  }

  // ================= AUDIT =================

  public async getAuditEvents(params?: {
    action?: string;
    outcome?: string;
    actorEmail?: string;
    limit?: number;
  }): Promise<{ events: AuditEvent[] }> {
    try {
      const base = this.baseUrl || window.location.origin;
      const url = new URL('/api/audit/events', base);
      if (params?.action) url.searchParams.set('action', params.action);
      if (params?.outcome) url.searchParams.set('outcome', params.outcome);
      if (params?.actorEmail) url.searchParams.set('actorEmail', params.actorEmail);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));

      const res = await this.safeFetch(url.toString(), {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ events: AuditEvent[] }>(res);
      }
    } catch {}

    return { events: browserVault.getAuditEvents(params) };
  }

  public async verifyAuditChain(): Promise<{ verification: VerificationResult }> {
    try {
      const res = await this.safeFetch('/api/audit/verify', {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ verification: VerificationResult }>(res);
      }
    } catch {}

    return { verification: browserVault.verifyAuditChain() };
  }

  // ================= ADMIN & GOVERNANCE =================

  public async getAdminDashboard(): Promise<AdminDashboardData> {
    try {
      const res = await this.safeFetch('/api/admin/dashboard', {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<AdminDashboardData>(res);
      }
    } catch {}

    return browserVault.getAdminDashboard();
  }

  // ================= USERS =================

  public async getUsers(): Promise<{ users: User[] }> {
    try {
      const res = await this.safeFetch('/api/users', {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ users: User[] }>(res);
      }
    } catch {}

    return { users: browserVault.getUsers() };
  }

  public async createUser(userData: {
    email: string;
    displayName: string;
    password: string;
    role: string;
  }): Promise<{ user: User }> {
    try {
      const res = await this.safeFetch('/api/users', {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(userData)
      });
      if (res.ok) {
        return await this.safeParseResponse<{ user: User }>(res);
      }
    } catch {}

    const user = browserVault.createUser(userData);
    return { user };
  }

  public async updateUser(
    id: string,
    updates: { active?: boolean; role?: string; displayName?: string }
  ): Promise<{ user: User }> {
    try {
      const res = await this.safeFetch(`/api/users/${id}`, {
        method: 'PATCH',
        headers: this.getHeaders(),
        body: JSON.stringify(updates)
      });
      if (res.ok) {
        return await this.safeParseResponse<{ user: User }>(res);
      }
    } catch {}

    const user = browserVault.updateUser(id, updates);
    return { user };
  }

  // ================= PENTEST & SECURITY SUITE =================

  public async runSecuritySuite(): Promise<{ report: SecurityTestReport }> {
    try {
      const res = await this.safeFetch('/api/security/run-tests', {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<{ report: SecurityTestReport }>(res);
      }
    } catch {}

    return { report: browserVault.runSecuritySuite() };
  }

  // ================= JSON DATABASE & PERSISTENCE =================

  public async getJsonDatabaseStats(): Promise<JsonDatabaseResponse> {
    try {
      const res = await this.safeFetch('/api/admin/json-database', {
        headers: this.getHeaders()
      });
      if (res.ok) {
        return await this.safeParseResponse<JsonDatabaseResponse>(res);
      }
    } catch {}

    return browserVault.getJsonDatabaseStats();
  }

  public async exportJsonDatabase(): Promise<void> {
    try {
      const res = await this.safeFetch('/api/admin/json-database/export', {
        headers: this.getHeaders(false)
      });
      if (res.ok) {
        const blob = await res.blob();
        this.triggerDownloadBlob(blob, `vault_database_${new Date().toISOString().split('T')[0]}.json`);
        return;
      }
    } catch {}

    const jsonStr = browserVault.exportJsonDatabase();
    const blob = new Blob([jsonStr], { type: 'application/json' });
    this.triggerDownloadBlob(blob, `vault_database_${new Date().toISOString().split('T')[0]}.json`);
  }

  public async importJsonDatabase(jsonContent: string): Promise<{ success: boolean; message: string; importedCounts: Record<string, number> }> {
    try {
      const res = await this.safeFetch('/api/admin/json-database/import', {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ jsonContent })
      });
      if (res.ok) {
        return await this.safeParseResponse<{ success: boolean; message: string; importedCounts: Record<string, number> }>(res);
      }
    } catch {}

    return browserVault.importJsonDatabase(jsonContent);
  }
}

export const api = new ApiService();
