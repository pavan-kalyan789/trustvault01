/**
 * Audit Trail & Verification API Router
 * Exposes tamper-evident event queries, document history,
 * and cryptographic HMAC-SHA256 chain integrity verification.
 */

import express, { type Response } from 'express';
import { auditEngine } from '../audit.js';
import { vaultStore } from '../store.js';
import {
  authenticateUser,
  canReadDocument,
  type AuthenticatedRequest
} from '../authz.js';
import type { AuditAction, AuditOutcome } from '../types.js';

export const auditRouter = express.Router();

/**
 * GET /api/audit/events
 * Admin can view system-wide events.
 * Non-admins can only view events in which they are actor or target!
 */
auditRouter.get('/events', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const action = req.query.action as AuditAction | undefined;
    const outcome = req.query.outcome as AuditOutcome | undefined;
    const actorEmail = req.query.actorEmail as string | undefined;
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 100;

    const allEvents = auditEngine.getEvents({ action, outcome, actorEmail, limit });

    if (user.role === 'admin') {
      res.json({ events: allEvents });
    } else {
      // Filter strictly to events involving this user
      const filtered = allEvents.filter(
        e => e.actorId === user.id || e.targetUserId === user.id
      );
      res.json({ events: filtered });
    }
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to retrieve audit events.' });
  }
});

/**
 * GET /api/audit/documents/:id
 * Retrieve audit history for a specific document
 */
auditRouter.get('/documents/:id', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const docId = req.params.id;
    const doc = await vaultStore.getDocumentById(docId);

    if (!doc) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    const canRead = await canReadDocument(user, doc);
    if (!canRead && user.role !== 'admin') {
      res.status(404).json({ error: 'NotFound', message: 'Document not found or access denied.' });
      return;
    }

    const docEvents = auditEngine.getEvents({ documentId: docId });
    res.json({ events: docEvents });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to fetch document audit history.' });
  }
});

/**
 * POST /api/audit/verify
 * Cryptographically verifies the HMAC-SHA256 hash chain
 */
auditRouter.post('/verify', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const verificationResult = auditEngine.verifyAuditChain();

    // Log the verification action itself
    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'AUDIT_VERIFICATION',
      outcome: verificationResult.isValid ? 'SUCCESS' : 'FAILURE',
      ip: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'unknown',
      metadata: {
        verifiedCount: verificationResult.verifiedCount,
        totalEvents: verificationResult.totalEvents,
        isValid: verificationResult.isValid,
        reason: verificationResult.reason || 'All hashes and links valid'
      }
    });

    res.json({ verification: verificationResult });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Audit verification execution failed.' });
  }
});

/**
 * GET /api/admin/audit-checkpoints
 * List anchored cryptographic checkpoints
 */
auditRouter.get('/checkpoints', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const checkpoints = auditEngine.getCheckpoints();
    res.json({ checkpoints });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to retrieve checkpoints.' });
  }
});
