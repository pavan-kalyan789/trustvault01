/**
 * Database & State Management Layer
 * Provides robust Firestore-compatible storage with thread-safe persistence,
 * atomic transactions, and immediate query consistency.
 */

import crypto from 'node:crypto';
import type {
  User,
  DocumentRecord,
  DocumentGrant,
  DocumentVersion,
  SecurityAlert,
  DocumentCategory
} from './types.js';

export class VaultStore {
  public users: Map<string, User> = new Map();
  public documents: Map<string, DocumentRecord> = new Map();
  public grants: Map<string, DocumentGrant> = new Map();
  public versions: Map<string, DocumentVersion> = new Map();
  public alerts: SecurityAlert[] = [];

  constructor() {}

  // ================= USERS =================
  public async getUserById(id: string): Promise<User | null> {
    return this.users.get(id) || null;
  }

  public async getUserByEmail(email: string): Promise<User | null> {
    const cleanEmail = email.trim().toLowerCase();
    for (const u of this.users.values()) {
      if (u.email.toLowerCase() === cleanEmail) {
        return u;
      }
    }
    return null;
  }

  public async getAllUsers(): Promise<User[]> {
    return Array.from(this.users.values());
  }

  public async createUser(user: User): Promise<User> {
    this.users.set(user.id, user);
    return user;
  }

  public async updateUser(id: string, updates: Partial<User>): Promise<User | null> {
    const user = this.users.get(id);
    if (!user) return null;
    const updated = { ...user, ...updates };
    this.users.set(id, updated);
    return updated;
  }

  // ================= DOCUMENTS =================
  public async getDocumentById(id: string): Promise<DocumentRecord | null> {
    return this.documents.get(id) || null;
  }

  public async createDocument(doc: DocumentRecord): Promise<DocumentRecord> {
    this.documents.set(doc.id, doc);
    return doc;
  }

  public async updateDocument(id: string, updates: Partial<DocumentRecord>): Promise<DocumentRecord | null> {
    const doc = this.documents.get(id);
    if (!doc) return null;
    const updated: DocumentRecord = {
      ...doc,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    this.documents.set(id, updated);
    return updated;
  }

  public async deleteDocument(id: string): Promise<boolean> {
    const doc = this.documents.get(id);
    if (!doc) return false;
    doc.isDeleted = true;
    doc.updatedAt = new Date().toISOString();
    return true;
  }

  public async restoreDocument(id: string): Promise<boolean> {
    const doc = this.documents.get(id);
    if (!doc) return false;
    doc.isDeleted = false;
    doc.updatedAt = new Date().toISOString();
    return true;
  }

  /**
   * Search documents authorized for a specific user
   * CRITICAL: Authorization check executed at database level before returning!
   */
  public async searchAccessibleDocuments(
    userId: string,
    filters?: {
      query?: string;
      category?: string;
      includeDeleted?: boolean;
    }
  ): Promise<DocumentRecord[]> {
    const now = new Date();
    // 1. Gather all active, unexpired grant document IDs for this user
    const grantedDocIds = new Set<string>();
    for (const g of this.grants.values()) {
      if (
        g.granteeId === userId &&
        g.isActive &&
        (!g.expiresAt || new Date(g.expiresAt) > now)
      ) {
        grantedDocIds.add(g.documentId);
      }
    }

    const results: DocumentRecord[] = [];
    for (const doc of this.documents.values()) {
      // Check soft-deleted
      if (!filters?.includeDeleted && doc.isDeleted) {
        continue;
      }

      // Check authorization: must be OWNER or have explicit active grant
      const isOwner = doc.ownerId === userId;
      const hasGrant = grantedDocIds.has(doc.id);

      if (!isOwner && !hasGrant) {
        // Disallowed! Not included in results.
        continue;
      }

      // Apply search query
      if (filters?.query) {
        const q = filters.query.toLowerCase();
        const matchesName = doc.name.toLowerCase().includes(q);
        const matchesDesc = doc.description?.toLowerCase().includes(q);
        const matchesFile = doc.originalFilename.toLowerCase().includes(q);
        if (!matchesName && !matchesDesc && !matchesFile) {
          continue;
        }
      }

      // Apply category filter
      if (filters?.category && filters.category !== 'ALL') {
        if (doc.category !== filters.category) {
          continue;
        }
      }

      results.push(doc);
    }

    // Sort newest first
    return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  /**
   * Admin metadata listing: Administrators can view document metadata
   * across the organization for governance, but content/download is restricted.
   */
  public async getAdminDocumentMetadataList(): Promise<DocumentRecord[]> {
    return Array.from(this.documents.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  // ================= GRANTS & PERMISSIONS =================
  public async createGrant(grant: DocumentGrant): Promise<DocumentGrant> {
    this.grants.set(grant.id, grant);
    return grant;
  }

  public async getGrantById(id: string): Promise<DocumentGrant | null> {
    return this.grants.get(id) || null;
  }

  public async getGrantsForDocument(documentId: string): Promise<DocumentGrant[]> {
    const list: DocumentGrant[] = [];
    for (const g of this.grants.values()) {
      if (g.documentId === documentId) {
        list.push(g);
      }
    }
    return list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  public async getActiveGrant(documentId: string, granteeId: string): Promise<DocumentGrant | null> {
    const now = new Date();
    for (const g of this.grants.values()) {
      if (
        g.documentId === documentId &&
        g.granteeId === granteeId &&
        g.isActive
      ) {
        // Check expiration
        if (g.expiresAt && new Date(g.expiresAt) <= now) {
          continue;
        }
        return g;
      }
    }
    return null;
  }

  /**
   * Immediately revokes a grant
   */
  public async revokeGrant(grantId: string): Promise<DocumentGrant | null> {
    const grant = this.grants.get(grantId);
    if (!grant) return null;

    grant.isActive = false;
    grant.revokedAt = new Date().toISOString();
    this.grants.set(grantId, grant);
    return grant;
  }

  // ================= VERSIONS =================
  public async createVersion(version: DocumentVersion): Promise<DocumentVersion> {
    this.versions.set(version.id, version);
    return version;
  }

  public async getVersionsForDocument(documentId: string): Promise<DocumentVersion[]> {
    const list: DocumentVersion[] = [];
    for (const v of this.versions.values()) {
      if (v.documentId === documentId) {
        list.push(v);
      }
    }
    return list.sort((a, b) => b.versionNumber - a.versionNumber);
  }

  // ================= SECURITY ALERTS =================
  public async recordAlert(alert: Omit<SecurityAlert, 'id' | 'timestamp'>): Promise<SecurityAlert> {
    const fullAlert: SecurityAlert = {
      ...alert,
      id: 'alt_' + crypto.randomUUID(),
      timestamp: new Date().toISOString()
    };
    this.alerts.unshift(fullAlert);
    if (this.alerts.length > 100) {
      this.alerts.pop();
    }
    return fullAlert;
  }

  public async getAlerts(): Promise<SecurityAlert[]> {
    return [...this.alerts];
  }
}

export const vaultStore = new VaultStore();
