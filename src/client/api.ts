/**
 * TrustVault API Client
 * Secure typed HTTP client with safe response parsing, network error resilience,
 * and zero raw stack trace exposure.
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

  /**
   * Safe fetch with network failure handling
   */
  private async safeFetch(url: string, init?: RequestInit): Promise<Response> {
    try {
      return await fetch(url, init);
    } catch (networkError: any) {
      throw new Error(
        'Unable to connect to the TrustVault security server. Please check your network connection.'
      );
    }
  }

  /**
   * Safe response parsing:
   * - Reads body as text first to prevent "Unexpected end of JSON input"
   * - Handles empty responses (0 bytes)
   * - Handles non-JSON HTML error pages (e.g., 502/504 Bad Gateway from proxies)
   * - Never exposes raw stack traces or internal exception details
   */
  private async safeParseResponse<T>(res: Response): Promise<T> {
    const rawText = await res.text().catch(() => '');
    let parsedData: any = null;

    if (rawText && rawText.trim().length > 0) {
      try {
        parsedData = JSON.parse(rawText);
      } catch {
        // Non-JSON response (e.g. HTML error page or raw proxy status)
        parsedData = null;
      }
    }

    if (!res.ok) {
      let errorMessage = `Request failed (HTTP ${res.status})`;

      if (parsedData && typeof parsedData === 'object') {
        errorMessage = parsedData.message || parsedData.error || errorMessage;
      } else if (rawText && rawText.length > 0 && rawText.length < 200 && !rawText.includes('<!DOCTYPE')) {
        errorMessage = rawText.trim();
      } else {
        // Human-friendly fallback messages based on status codes
        switch (res.status) {
          case 400:
            errorMessage = 'Invalid request parameters format.';
            break;
          case 401:
            errorMessage = 'Invalid email or password.';
            break;
          case 403:
            errorMessage = 'Account deactivated or insufficient permissions.';
            break;
          case 404:
            errorMessage = 'Requested resource not found or access denied.';
            break;
          case 409:
            errorMessage = 'Resource conflict: record already exists.';
            break;
          case 429:
            errorMessage = 'Rate limit exceeded. Please wait a minute before retrying.';
            break;
          case 500:
          case 502:
          case 503:
          case 504:
            errorMessage = 'TrustVault security service is temporarily unavailable. Please retry in a moment.';
            break;
          default:
            errorMessage = `Server returned HTTP status ${res.status}.`;
        }
      }

      throw new Error(errorMessage);
    }

    // 204 No Content response
    if (res.status === 204) {
      return {} as T;
    }

    // Success response must contain valid JSON payload
    if (parsedData === null) {
      throw new Error('Security server returned an empty or invalid JSON response.');
    }

    return parsedData as T;
  }

  // ================= AUTHENTICATION =================

  /**
   * Authenticate via email & password
   */
  public async login(email: string, password: string): Promise<AuthResponse> {
    const res = await this.safeFetch('/api/auth/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim(), password })
    });
    const data = await this.safeParseResponse<AuthResponse>(res);
    if (data.token) {
      this.setToken(data.token);
    }
    return data;
  }

  /**
   * Authenticate via verified demo account profile
   */
  public async demoLogin(role: 'admin' | 'owner' | 'viewer' | 'other'): Promise<AuthResponse> {
    const res = await this.safeFetch('/api/auth/demo-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    });
    const data = await this.safeParseResponse<AuthResponse>(res);
    if (data.token) {
      this.setToken(data.token);
    }
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
    const res = await this.safeFetch('/api/auth/me', {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ user: User }>(res);
  }

  public async getFirebaseStatus(): Promise<FirebaseStatusInfo> {
    const res = await this.safeFetch('/api/auth/firebase-status', {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<FirebaseStatusInfo>(res);
  }

  // ================= DOCUMENTS =================

  public async getDocuments(params?: {
    q?: string;
    category?: string;
    adminView?: boolean;
  }): Promise<{ documents: DocumentRecord[] }> {
    const url = new URL('/api/documents', window.location.origin);
    if (params?.q) url.searchParams.set('q', params.q);
    if (params?.category) url.searchParams.set('category', params.category);
    if (params?.adminView) url.searchParams.set('adminView', 'true');

    const res = await this.safeFetch(url.toString(), {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ documents: DocumentRecord[] }>(res);
  }

  public async getDocument(id: string): Promise<{ document: DocumentRecord; userCanDownload: boolean }> {
    const res = await this.safeFetch(`/api/documents/${id}`, {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ document: DocumentRecord; userCanDownload: boolean }>(res);
  }

  public async uploadDocument(formData: FormData): Promise<{ document: DocumentRecord }> {
    const res = await this.safeFetch('/api/documents', {
      method: 'POST',
      headers: {
        Authorization: this.token ? `Bearer ${this.token}` : ''
      },
      body: formData
    });
    return this.safeParseResponse<{ document: DocumentRecord }>(res);
  }

  public async updateDocument(id: string, updates: Partial<DocumentRecord>): Promise<{ document: DocumentRecord }> {
    const res = await this.safeFetch(`/api/documents/${id}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    return this.safeParseResponse<{ document: DocumentRecord }>(res);
  }

  public async deleteDocument(id: string): Promise<{ success: boolean }> {
    const res = await this.safeFetch(`/api/documents/${id}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ success: boolean }>(res);
  }

  public async restoreDocument(id: string): Promise<{ success: boolean }> {
    const res = await this.safeFetch(`/api/documents/${id}/restore`, {
      method: 'POST',
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ success: boolean }>(res);
  }

  public async getVersions(id: string): Promise<{ versions: DocumentVersion[] }> {
    const res = await this.safeFetch(`/api/documents/${id}/versions`, {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ versions: DocumentVersion[] }>(res);
  }

  public async uploadVersion(id: string, formData: FormData): Promise<{ version: DocumentVersion }> {
    const res = await this.safeFetch(`/api/documents/${id}/versions`, {
      method: 'POST',
      headers: {
        Authorization: this.token ? `Bearer ${this.token}` : ''
      },
      body: formData
    });
    return this.safeParseResponse<{ version: DocumentVersion }>(res);
  }

  public async downloadDocument(id: string, filename: string): Promise<void> {
    const res = await this.safeFetch(`/api/documents/${id}/download`, {
      headers: this.getHeaders(false)
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      let cleanMsg = 'Failed to download document: access denied or file unavailable.';
      try {
        const parsed = JSON.parse(errText);
        cleanMsg = parsed.message || parsed.error || cleanMsg;
      } catch {}
      throw new Error(cleanMsg);
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
    const res = await this.safeFetch(`/api/documents/${id}/preview`, {
      headers: this.getHeaders(false)
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      let cleanMsg = 'Access denied for document preview.';
      try {
        const parsed = JSON.parse(errText);
        cleanMsg = parsed.message || parsed.error || cleanMsg;
      } catch {}
      throw new Error(cleanMsg);
    }

    const blob = await res.blob();
    return window.URL.createObjectURL(blob);
  }

  // ================= PERMISSIONS =================

  public async getPermissions(documentId: string): Promise<{ grants: DocumentGrant[] }> {
    const res = await this.safeFetch(`/api/documents/${documentId}/permissions`, {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ grants: DocumentGrant[] }>(res);
  }

  public async grantPermission(
    documentId: string,
    granteeEmail: string,
    permissionLevel: 'READ' | 'EDIT',
    expiresAt?: string | null
  ): Promise<{ grant: DocumentGrant }> {
    const res = await this.safeFetch(`/api/documents/${documentId}/permissions`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ granteeEmail, permissionLevel, expiresAt })
    });
    return this.safeParseResponse<{ grant: DocumentGrant }>(res);
  }

  public async revokePermission(documentId: string, grantId: string): Promise<{ success: boolean; message: string }> {
    const res = await this.safeFetch(`/api/documents/${documentId}/permissions/${grantId}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ success: boolean; message: string }>(res);
  }

  // ================= AUDIT =================

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

    const res = await this.safeFetch(url.toString(), {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ events: AuditEvent[] }>(res);
  }

  public async verifyAuditChain(): Promise<{ verification: VerificationResult }> {
    const res = await this.safeFetch('/api/audit/verify', {
      method: 'POST',
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ verification: VerificationResult }>(res);
  }

  // ================= ADMIN & GOVERNANCE =================

  public async getAdminDashboard(): Promise<AdminDashboardData> {
    const res = await this.safeFetch('/api/admin/dashboard', {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<AdminDashboardData>(res);
  }

  // ================= USERS =================

  public async getUsers(): Promise<{ users: User[] }> {
    const res = await this.safeFetch('/api/users', {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ users: User[] }>(res);
  }

  public async createUser(userData: {
    email: string;
    displayName: string;
    password: string;
    role: string;
  }): Promise<{ user: User }> {
    const res = await this.safeFetch('/api/users', {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(userData)
    });
    return this.safeParseResponse<{ user: User }>(res);
  }

  public async updateUser(
    id: string,
    updates: { active?: boolean; role?: string; displayName?: string }
  ): Promise<{ user: User }> {
    const res = await this.safeFetch(`/api/users/${id}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    return this.safeParseResponse<{ user: User }>(res);
  }

  // ================= PENTEST & SECURITY SUITE =================

  public async runSecuritySuite(): Promise<{ report: SecurityTestReport }> {
    const res = await this.safeFetch('/api/security/run-tests', {
      method: 'POST',
      headers: this.getHeaders()
    });
    return this.safeParseResponse<{ report: SecurityTestReport }>(res);
  }

  // ================= JSON DATABASE & PERSISTENCE =================

  public async getJsonDatabaseStats(): Promise<JsonDatabaseResponse> {
    const res = await this.safeFetch('/api/admin/json-database', {
      headers: this.getHeaders()
    });
    return this.safeParseResponse<JsonDatabaseResponse>(res);
  }

  public async exportJsonDatabase(): Promise<void> {
    const res = await this.safeFetch('/api/admin/json-database/export', {
      headers: this.getHeaders(false)
    });
    if (!res.ok) {
      throw new Error('Failed to export connected JSON database.');
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vault_database_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  public async importJsonDatabase(jsonContent: string): Promise<{ success: boolean; message: string; importedCounts: Record<string, number> }> {
    const res = await this.safeFetch('/api/admin/json-database/import', {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ jsonContent })
    });
    return this.safeParseResponse<{ success: boolean; message: string; importedCounts: Record<string, number> }>(res);
  }
}

export const api = new ApiService();

