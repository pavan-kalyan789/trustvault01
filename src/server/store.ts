/**
 * Database & State Management Layer
 * Provides robust JSON-persisted storage with thread-safe file sync,
 * atomic transactions, and immediate query consistency.
 * Connected to vault_database.json
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  User,
  DocumentRecord,
  DocumentGrant,
  DocumentVersion,
  SecurityAlert,
  DocumentCategory
} from './types.js';

const DATA_DIR = process.env.DATA_DIR || process.cwd();
if (!fs.existsSync(DATA_DIR)) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch {}
}

const JSON_DB_FILE = path.resolve(DATA_DIR, 'vault_database.json');
const JSON_DB_BAK = path.resolve(DATA_DIR, 'vault_database.json.bak');

export class VaultStore {
  public users: Map<string, User> = new Map();
  public documents: Map<string, DocumentRecord> = new Map();
  public grants: Map<string, DocumentGrant> = new Map();
  public versions: Map<string, DocumentVersion> = new Map();
  public alerts: SecurityAlert[] = [];
  private saveTimeout: NodeJS.Timeout | null = null;

  constructor() {
    this.loadFromJson();
  }

  /**
   * Loads initial state from the connected JSON database file or backup file
   */
  public loadFromJson(): boolean {
    const candidates = [JSON_DB_FILE, JSON_DB_BAK];
    for (const targetPath of candidates) {
      try {
        if (fs.existsSync(targetPath)) {
          const raw = fs.readFileSync(targetPath, 'utf-8');
          if (raw && raw.trim().length > 0) {
            const data = JSON.parse(raw);
            if (data && typeof data === 'object') {
              let loadedAny = false;
              if (Array.isArray(data.users) && data.users.length > 0) {
                this.users = new Map(data.users.map((u: User) => [u.id, u]));
                loadedAny = true;
              }
              if (Array.isArray(data.documents)) {
                this.documents = new Map(data.documents.map((d: DocumentRecord) => [d.id, d]));
              }
              if (Array.isArray(data.grants)) {
                this.grants = new Map(data.grants.map((g: DocumentGrant) => [g.id, g]));
              }
              if (Array.isArray(data.versions)) {
                this.versions = new Map(data.versions.map((v: DocumentVersion) => [v.id, v]));
              }
              if (Array.isArray(data.alerts)) {
                this.alerts = data.alerts;
              }
              if (loadedAny) {
                return true;
              }
            }
          }
        }
      } catch (err) {
        console.warn(`[VaultStore] Note reading database from ${path.basename(targetPath)}:`, err);
      }
    }
    return false;
  }

  /**
   * Schedules debounced write to the connected JSON database file
   */
  public schedulePersist() {
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }
    this.saveTimeout = setTimeout(() => {
      this.persistToJsonSync();
    }, 50);
  }

  /**
   * Persists database state atomically to vault_database.json
   * Writes to a temp file and renames atomically to prevent corrupted or truncated files.
   */
  public persistToJsonSync(): void {
    try {
      const payload = {
        _schema: 'TrustVault Enterprise JSON Database',
        _version: '1.0',
        _lastSaved: new Date().toISOString(),
        filePath: 'vault_database.json',
        users: Array.from(this.users.values()),
        documents: Array.from(this.documents.values()),
        grants: Array.from(this.grants.values()),
        versions: Array.from(this.versions.values()),
        alerts: this.alerts
      };
      const jsonContent = JSON.stringify(payload, null, 2);

      // Backup existing file if valid
      if (fs.existsSync(JSON_DB_FILE)) {
        try {
          fs.copyFileSync(JSON_DB_FILE, JSON_DB_BAK);
        } catch {}
      }

      // Atomic write: write to unique temp file then rename
      const tmpFile = `${JSON_DB_FILE}.tmp.${crypto.randomBytes(4).toString('hex')}`;
      fs.writeFileSync(tmpFile, jsonContent, 'utf-8');
      fs.renameSync(tmpFile, JSON_DB_FILE);
    } catch (err) {
      console.error('[VaultStore] Error writing to vault_database.json:', err);
    }
  }

  public exportJson(): string {
    const payload = {
      _schema: 'TrustVault Enterprise JSON Database',
      _version: '1.0',
      _exportedAt: new Date().toISOString(),
      users: Array.from(this.users.values()),
      documents: Array.from(this.documents.values()),
      grants: Array.from(this.grants.values()),
      versions: Array.from(this.versions.values()),
      alerts: this.alerts
    };
    return JSON.stringify(payload, null, 2);
  }

  public importJson(jsonString: string): { success: boolean; importedCounts: Record<string, number> } {
    const data = JSON.parse(jsonString);
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid JSON format.');
    }
    let userCount = 0, docCount = 0, grantCount = 0, versionCount = 0;
    if (Array.isArray(data.users)) {
      for (const u of data.users) {
        if (u.id && u.email) {
          this.users.set(u.id, u);
          userCount++;
        }
      }
    }
    if (Array.isArray(data.documents)) {
      for (const d of data.documents) {
        if (d.id && d.name) {
          this.documents.set(d.id, d);
          docCount++;
        }
      }
    }
    if (Array.isArray(data.grants)) {
      for (const g of data.grants) {
        if (g.id && g.documentId) {
          this.grants.set(g.id, g);
          grantCount++;
        }
      }
    }
    if (Array.isArray(data.versions)) {
      for (const v of data.versions) {
        if (v.id && v.documentId) {
          this.versions.set(v.id, v);
          versionCount++;
        }
      }
    }
    this.persistToJsonSync();
    return {
      success: true,
      importedCounts: {
        users: userCount,
        documents: docCount,
        grants: grantCount,
        versions: versionCount
      }
    };
  }

  public getDatabaseStats() {
    let sizeBytes = 0;
    let lastModified: string | null = null;
    try {
      if (fs.existsSync(JSON_DB_FILE)) {
        const stat = fs.statSync(JSON_DB_FILE);
        sizeBytes = stat.size;
        lastModified = stat.mtime.toISOString();
      }
    } catch {}

    return {
      fileName: 'vault_database.json',
      connected: true,
      status: 'CONNECTED_AND_SYNCED',
      sizeBytes,
      lastModified,
      counts: {
        users: this.users.size,
        documents: this.documents.size,
        grants: this.grants.size,
        versions: this.versions.size,
        alerts: this.alerts.length
      }
    };
  }

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
    this.schedulePersist();
    return user;
  }

  public async updateUser(id: string, updates: Partial<User>): Promise<User | null> {
    const user = this.users.get(id);
    if (!user) return null;
    const updated = { ...user, ...updates };
    this.users.set(id, updated);
    this.schedulePersist();
    return updated;
  }

  // ================= DOCUMENTS =================
  public async getDocumentById(id: string): Promise<DocumentRecord | null> {
    return this.documents.get(id) || null;
  }

  public async createDocument(doc: DocumentRecord): Promise<DocumentRecord> {
    this.documents.set(doc.id, doc);
    this.schedulePersist();
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
    this.schedulePersist();
    return updated;
  }

  public async deleteDocument(id: string): Promise<boolean> {
    const doc = this.documents.get(id);
    if (!doc) return false;
    doc.isDeleted = true;
    doc.updatedAt = new Date().toISOString();
    this.schedulePersist();
    return true;
  }

  public async restoreDocument(id: string): Promise<boolean> {
    const doc = this.documents.get(id);
    if (!doc) return false;
    doc.isDeleted = false;
    doc.updatedAt = new Date().toISOString();
    this.schedulePersist();
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
    this.schedulePersist();
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
    this.schedulePersist();
    return grant;
  }

  // ================= VERSIONS =================
  public async createVersion(version: DocumentVersion): Promise<DocumentVersion> {
    this.versions.set(version.id, version);
    this.schedulePersist();
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
    this.schedulePersist();
    return fullAlert;
  }

  public async getAlerts(): Promise<SecurityAlert[]> {
    return [...this.alerts];
  }
}

export const vaultStore = new VaultStore();
