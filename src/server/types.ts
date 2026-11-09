/**
 * TrustVault - Data Models & Types
 * Enterprise Document Security & Audit Trail
 */

export type UserRole = 'admin' | 'owner' | 'viewer';

export interface User {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
  passwordHash: string; // Stored securely
  active: boolean;
  createdAt: string;
  lastLoginAt?: string;
}

export type DocumentCategory =
  | 'Contracts'
  | 'Finance'
  | 'HR'
  | 'Legal'
  | 'Technical'
  | 'Audit'
  | 'Confidential'
  | 'General';

export interface DocumentRecord {
  id: string;
  name: string;
  description: string;
  originalFilename: string;
  ownerId: string;
  ownerEmail: string;
  category: DocumentCategory;
  mimeType: string;
  size: number;
  sha256Hash: string;
  storageKey: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  isDeleted: boolean;
  retentionStatus: 'active' | 'retained' | 'archived';
}

export type PermissionLevel = 'READ' | 'EDIT' | 'OWNER';

export interface DocumentGrant {
  id: string;
  documentId: string;
  grantorId: string;
  grantorEmail: string;
  granteeId: string;
  granteeEmail: string;
  permissionLevel: PermissionLevel;
  createdAt: string;
  expiresAt?: string | null;
  revokedAt?: string | null;
  isActive: boolean;
}

export interface DocumentVersion {
  id: string;
  documentId: string;
  versionNumber: number;
  storageKey: string;
  sha256Hash: string;
  size: number;
  originalFilename: string;
  mimeType: string;
  createdBy: string;
  createdByEmail: string;
  createdAt: string;
  changeDescription: string;
}

export type AuditAction =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'LOGOUT'
  | 'DOCUMENT_UPLOAD'
  | 'DOCUMENT_VIEW'
  | 'DOCUMENT_DOWNLOAD'
  | 'DOCUMENT_UPDATE'
  | 'DOCUMENT_VERSION_CREATED'
  | 'DOCUMENT_DELETE'
  | 'DOCUMENT_RESTORE'
  | 'PERMISSION_GRANTED'
  | 'PERMISSION_REVOKED'
  | 'ACCESS_DENIED'
  | 'USER_CREATED'
  | 'USER_DISABLED'
  | 'ROLE_CHANGED'
  | 'ADMIN_ACTION'
  | 'AUDIT_VERIFICATION';

export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILURE';

export interface AuditEvent {
  id: string;
  actorId: string;
  actorEmail: string;
  actorRole: UserRole | 'anonymous';
  action: AuditAction;
  documentId?: string | null;
  targetUserId?: string | null;
  timestamp: string;
  outcome: AuditOutcome;
  requestId: string;
  ip: string;
  userAgent: string;
  metadata: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export interface AuditCheckpoint {
  id: string;
  timestamp: string;
  lastEventId: string;
  lastEventHash: string;
  totalEventsCount: number;
  signature: string;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: string;
  description: string;
  actorId?: string;
  actorEmail?: string;
  documentId?: string;
  ip?: string;
  details?: Record<string, unknown>;
}

export interface AuthSession {
  token: string;
  user: Omit<User, 'passwordHash'>;
  expiresAt: number;
}
