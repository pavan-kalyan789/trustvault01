/**
 * Document Permission Management Router
 * Supports explicit per-document permissions, self-grant prevention,
 * and immediate access revocation.
 */

import crypto from 'node:crypto';
import express, { type Response } from 'express';
import { z } from 'zod';
import { vaultStore } from '../store.js';
import { auditEngine } from '../audit.js';
import {
  authenticateUser,
  canManageDocumentPermissions,
  type AuthenticatedRequest
} from '../authz.js';
import type { DocumentGrant, PermissionLevel } from '../types.js';

export const permissionsRouter = express.Router();

/**
 * GET /api/documents/:id/permissions
 * List grants for document. ONLY the document OWNER can manage/view permissions.
 */
permissionsRouter.get('/:id/permissions', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const doc = await vaultStore.getDocumentById(req.params.id);

    if (!doc) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    if (!canManageDocumentPermissions(user, doc)) {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { attemptedAction: 'LIST_PERMISSIONS', documentId: doc.id }
      });

      res.status(403).json({ error: 'Forbidden', message: 'Only the document owner can manage permissions.' });
      return;
    }

    const grants = await vaultStore.getGrantsForDocument(doc.id);
    res.json({ grants });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to retrieve permissions.' });
  }
});

const GrantPermissionSchema = z.object({
  granteeEmail: z.string().email(),
  permissionLevel: z.enum(['READ', 'EDIT']),
  expiresAt: z.string().datetime().optional().nullable()
});

/**
 * POST /api/documents/:id/permissions
 * Explicitly grant READ or EDIT permission
 */
permissionsRouter.post('/:id/permissions', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const doc = await vaultStore.getDocumentById(req.params.id);

    if (!doc) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    if (!canManageDocumentPermissions(user, doc)) {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { attemptedAction: 'GRANT_PERMISSION', documentId: doc.id }
      });

      res.status(403).json({ error: 'Forbidden', message: 'Only the document owner can grant permissions.' });
      return;
    }

    const parse = GrantPermissionSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'BadRequest', message: parse.error.issues[0].message });
      return;
    }

    const { granteeEmail, permissionLevel, expiresAt } = parse.data;

    // Look up grantee
    const grantee = await vaultStore.getUserByEmail(granteeEmail);
    if (!grantee) {
      res.status(404).json({ error: 'NotFound', message: `No user found with email ${granteeEmail}.` });
      return;
    }

    // Rule: User cannot grant permission to themselves
    if (grantee.id === user.id) {
      res.status(400).json({
        error: 'BadRequest',
        message: 'Owner already possesses full rights; self-grants are disallowed.'
      });
      return;
    }

    // Check if grantee already has an active grant, revoke previous if replacing
    const existing = await vaultStore.getActiveGrant(doc.id, grantee.id);
    if (existing) {
      await vaultStore.revokeGrant(existing.id);
    }

    const grant: DocumentGrant = {
      id: 'grnt_' + crypto.randomUUID(),
      documentId: doc.id,
      grantorId: user.id,
      grantorEmail: user.email,
      granteeId: grantee.id,
      granteeEmail: grantee.email,
      permissionLevel: permissionLevel as PermissionLevel,
      createdAt: new Date().toISOString(),
      expiresAt: expiresAt || null,
      isActive: true
    };

    await vaultStore.createGrant(grant);

    // Audit log
    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'PERMISSION_GRANTED',
      documentId: doc.id,
      targetUserId: grantee.id,
      outcome: 'SUCCESS',
      ip: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'unknown',
      metadata: {
        documentName: doc.name,
        granteeEmail: grantee.email,
        permissionLevel,
        expiresAt: expiresAt || null
      }
    });

    res.status(201).json({ grant });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to create permission grant.' });
  }
});

/**
 * DELETE /api/documents/:id/permissions/:grantId
 * IMMEDIATE ACCESS REVOCATION
 * Revokes an existing permission grant. Takes effect instantaneously on all subsequent requests!
 */
permissionsRouter.delete('/:id/permissions/:grantId', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const doc = await vaultStore.getDocumentById(req.params.id);

    if (!doc) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    // Check ownership
    if (!canManageDocumentPermissions(user, doc)) {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { attemptedAction: 'REVOKE_PERMISSION', documentId: doc.id }
      });

      res.status(403).json({ error: 'Forbidden', message: 'Only the document owner can revoke permissions.' });
      return;
    }

    const grantId = req.params.grantId;
    const grant = await vaultStore.getGrantById(grantId);

    if (!grant || grant.documentId !== doc.id) {
      res.status(404).json({ error: 'NotFound', message: 'Permission grant record not found.' });
      return;
    }

    // Revoke atomically
    const revoked = await vaultStore.revokeGrant(grantId);

    // Audit log
    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'PERMISSION_REVOKED',
      documentId: doc.id,
      targetUserId: grant.granteeId,
      outcome: 'SUCCESS',
      ip: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'unknown',
      metadata: {
        documentName: doc.name,
        granteeEmail: grant.granteeEmail,
        revokedLevel: grant.permissionLevel
      }
    });

    res.json({
      success: true,
      message: `Permission for ${grant.granteeEmail} was immediately revoked.`,
      grant: revoked
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to revoke permission.' });
  }
});
