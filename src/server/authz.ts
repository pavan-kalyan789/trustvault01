/**
 * Centralized Server-Side Authorization Service
 * Enforces least-privilege, IDOR protection, role-based controls,
 * and immediate permission checks on every protected request.
 */

import type { Request, Response, NextFunction } from 'express';
import { vaultStore } from './store.js';
import { auditEngine } from './audit.js';
import type { User, DocumentRecord, PermissionLevel, UserRole } from './types.js';

// Extend Express Request type
export interface AuthenticatedRequest extends Request {
  user?: User;
}

// In-memory session store (mapping token -> { userId, expiresAt })
export const activeSessions = new Map<string, { userId: string; expiresAt: number }>();

/**
 * MUTATION TESTING HOOK:
 * Used solely to verify that disabling authorization causes automated security tests to fail.
 * Must NEVER be left enabled in production!
 */
export let mutationTestBypassAuthz = false;
export function setMutationTestBypass(val: boolean) {
  mutationTestBypassAuthz = val;
}

/**
 * Authenticates user from Bearer Token or Cookie
 * Re-validates active status on EVERY call to block disabled users immediately!
 */
export async function authenticateUser(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    } else if (req.cookies && req.cookies['tv_token']) {
      token = req.cookies['tv_token'];
    }

    if (!token) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication token required.'
      });
      return;
    }

    const session = activeSessions.get(token);
    if (!session) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired session token.'
      });
      return;
    }

    if (Date.now() > session.expiresAt) {
      activeSessions.delete(token);
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Session has expired. Please re-authenticate.'
      });
      return;
    }

    // Retrieve user from DB to verify current state
    const user = await vaultStore.getUserById(session.userId);
    if (!user) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'User account not found.'
      });
      return;
    }

    // Immediately reject disabled accounts
    if (!user.active) {
      // Record access attempt by disabled account
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        outcome: 'DENIED',
        ip: req.ip || req.socket.remoteAddress || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { reason: 'User account disabled' }
      });

      res.status(403).json({
        error: 'Forbidden',
        message: 'Account is deactivated. Contact an administrator.'
      });
      return;
    }

    req.user = user;
    next();
  } catch (err) {
    res.status(500).json({
      error: 'InternalServerError',
      message: 'Authentication processing failed.'
    });
  }
}

/**
 * Enforces role restriction
 */
export function requireRole(allowedRoles: UserRole[]) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      await auditEngine.logEvent({
        actorId: req.user.id,
        actorEmail: req.user.email,
        actorRole: req.user.role,
        action: 'ACCESS_DENIED',
        outcome: 'DENIED',
        ip: req.ip || req.socket.remoteAddress || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { requiredRoles: allowedRoles, currentRole: req.user.role, path: req.path }
      });

      res.status(403).json({
        error: 'Forbidden',
        message: `Role '${req.user.role}' is not authorized to access this resource.`
      });
      return;
    }

    next();
  };
}

/**
 * Evaluates whether a user can READ a document.
 * CRITICAL RULE:
 * 1. Owner can always read their own document.
 * 2. Any user with an active, unexpired grant of 'READ', 'EDIT', or 'OWNER' can read.
 * 3. Administrator CANNOT automatically read/download documents unless explicitly granted!
 */
export async function canReadDocument(user: User, doc: DocumentRecord): Promise<boolean> {
  if (mutationTestBypassAuthz) {
    return true; // Bypass solely during mutation testing!
  }

  // Owner always has full access
  if (doc.ownerId === user.id) {
    return true;
  }

  // Check active grant in database
  const grant = await vaultStore.getActiveGrant(doc.id, user.id);
  if (grant && grant.isActive) {
    if (grant.expiresAt && new Date(grant.expiresAt) <= new Date()) {
      return false; // Expired
    }
    return ['READ', 'EDIT', 'OWNER'].includes(grant.permissionLevel);
  }

  return false;
}

/**
 * Evaluates whether a user can EDIT a document.
 */
export async function canEditDocument(user: User, doc: DocumentRecord): Promise<boolean> {
  if (mutationTestBypassAuthz) return true;

  if (doc.ownerId === user.id) return true;

  const grant = await vaultStore.getActiveGrant(doc.id, user.id);
  if (grant && grant.isActive) {
    if (grant.expiresAt && new Date(grant.expiresAt) <= new Date()) {
      return false;
    }
    return ['EDIT', 'OWNER'].includes(grant.permissionLevel);
  }

  return false;
}

/**
 * Evaluates whether a user can DELETE or RESTORE a document.
 * Only the owner can delete or restore.
 */
export async function canDeleteDocument(user: User, doc: DocumentRecord): Promise<boolean> {
  if (mutationTestBypassAuthz) return true;
  return doc.ownerId === user.id;
}

/**
 * Evaluates whether a user can MANAGE PERMISSIONS on a document.
 * Only the owner can manage permissions.
 */
export async function canManageDocumentPermissions(user: User, doc: DocumentRecord): Promise<boolean> {
  if (mutationTestBypassAuthz) return true;
  return doc.ownerId === user.id;
}

/**
 * Express middleware to require specific document access level
 * Returns 404 (Not Found) on unauthorized access to prevent existence disclosure!
 */
export function requireDocumentAccess(requiredLevel: 'READ' | 'EDIT' | 'OWNER') {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }

    const docId = req.params.id;
    if (!docId) {
      res.status(400).json({ error: 'BadRequest', message: 'Document ID is required.' });
      return;
    }

    const doc = await vaultStore.getDocumentById(docId);
    if (!doc) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    // Check soft-deleted
    if (doc.isDeleted && req.path.indexOf('/restore') === -1 && req.method !== 'GET') {
      res.status(404).json({ error: 'NotFound', message: 'Document has been deleted.' });
      return;
    }

    let authorized = false;
    if (requiredLevel === 'READ') {
      authorized = await canReadDocument(user, doc);
    } else if (requiredLevel === 'EDIT') {
      authorized = await canEditDocument(user, doc);
    } else if (requiredLevel === 'OWNER') {
      authorized = await canManageDocumentPermissions(user, doc);
    }

    if (!authorized) {
      // Log ACCESS_DENIED to tamper-evident audit trail!
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || req.socket.remoteAddress || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          attemptedLevel: requiredLevel,
          documentName: doc.name,
          ownerId: doc.ownerId,
          path: req.originalUrl
        }
      });

      // Record security alert if repeated or high sensitivity
      if (doc.category === 'Confidential' || user.role === 'admin') {
        await vaultStore.recordAlert({
          severity: user.role === 'admin' ? 'HIGH' : 'MEDIUM',
          type: 'UNAUTHORIZED_ACCESS_ATTEMPT',
          description: `Unauthorized access attempt to document '${doc.name}' (${doc.id}) by user ${user.email} [role: ${user.role}].`,
          actorId: user.id,
          actorEmail: user.email,
          documentId: doc.id,
          ip: req.ip || '127.0.0.1'
        });
      }

      // Return 404 to avoid leaking document existence to unauthorized callers (anti-IDOR)
      res.status(404).json({
        error: 'NotFound',
        message: 'Document not found or access denied.'
      });
      return;
    }

    next();
  };
}
