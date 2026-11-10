/**
 * Admin Governance & Security Overview Router
 * Comprehensive security telemetry, alert streams, and audit health metrics.
 */

import express, { type Response } from 'express';
import { vaultStore } from '../store.js';
import { auditEngine } from '../audit.js';
import {
  authenticateUser,
  requireRole,
  type AuthenticatedRequest
} from '../authz.js';

export const adminRouter = express.Router();

/**
 * GET /api/admin/dashboard
 * Aggregates security posture, activity volumes, and audit verification health
 */
adminRouter.get('/dashboard', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const allUsers = await vaultStore.getAllUsers();
    const activeUsers = allUsers.filter(u => u.active).length;

    const allDocs = await vaultStore.getAdminDocumentMetadataList();
    const activeDocs = allDocs.filter(d => !d.isDeleted).length;
    const deletedDocs = allDocs.filter(d => d.isDeleted).length;

    const allGrants = Array.from(vaultStore.grants.values());
    const activeGrants = allGrants.filter(g => g.isActive).length;
    const revokedGrants = allGrants.filter(g => !g.isActive).length;

    const allEvents = auditEngine.getEvents({ limit: 500 });
    const deniedEvents = allEvents.filter(e => e.outcome === 'DENIED');
    const downloadEvents = allEvents.filter(e => e.action === 'DOCUMENT_DOWNLOAD' && e.outcome === 'SUCCESS');
    const uploadEvents = allEvents.filter(e => e.action === 'DOCUMENT_UPLOAD' && e.outcome === 'SUCCESS');

    // Run audit verification status
    const auditStatus = auditEngine.verifyAuditChain();
    const alerts = await vaultStore.getAlerts();

    // Category breakdown
    const categoryCounts: Record<string, number> = {};
    for (const d of allDocs) {
      categoryCounts[d.category] = (categoryCounts[d.category] || 0) + 1;
    }

    res.json({
      metrics: {
        totalUsers: allUsers.length,
        activeUsers,
        totalDocuments: allDocs.length,
        activeDocuments: activeDocs,
        deletedDocuments: deletedDocs,
        totalGrants: allGrants.length,
        activeGrants,
        revokedGrants,
        totalDownloads: downloadEvents.length,
        totalUploads: uploadEvents.length,
        deniedAccessAttempts: deniedEvents.length,
        auditChainStatus: auditStatus.isValid ? 'SECURE_AND_VERIFIED' : 'INTEGRITY_COMPROMISED',
        totalAuditEvents: auditStatus.totalEvents
      },
      categoryCounts,
      recentAlerts: alerts.slice(0, 10),
      recentDeniedAttempts: deniedEvents.slice(0, 10),
      recentActivity: allEvents.slice(0, 15)
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to aggregate admin telemetry.' });
  }
});

/**
 * GET /api/admin/security-alerts
 */
adminRouter.get('/security-alerts', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const alerts = await vaultStore.getAlerts();
    res.json({ alerts });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to retrieve security alerts.' });
  }
});

/**
 * GET /api/admin/json-database
 * Retrieves status, file connection, and storage stats for connected JSON files
 */
adminRouter.get('/json-database', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const dbStats = vaultStore.getDatabaseStats();
    const auditStats = auditEngine.getAuditStats();

    res.json({
      success: true,
      database: dbStats,
      audit: auditStats,
      persistedAt: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'InternalServerError', message: 'Failed to retrieve JSON database status.' });
  }
});

/**
 * GET /api/admin/json-database/export
 * Exports the complete connected JSON database file for backup or local migration
 */
adminRouter.get('/json-database/export', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const jsonString = vaultStore.exportJson();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="vault_database_export.json"');
    res.send(jsonString);
  } catch (err) {
    res.status(500).json({ success: false, error: 'InternalServerError', message: 'Failed to export JSON database.' });
  }
});

/**
 * POST /api/admin/json-database/import
 * Imports records from a provided JSON database into the active vault store
 */
adminRouter.post('/json-database/import', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { jsonContent } = req.body;
    if (!jsonContent || typeof jsonContent !== 'string') {
      res.status(400).json({ success: false, error: 'BadRequest', message: 'jsonContent string is required.' });
      return;
    }

    const result = vaultStore.importJson(jsonContent);

    if (req.user) {
      await auditEngine.logEvent({
        actorId: req.user.id,
        actorEmail: req.user.email,
        actorRole: req.user.role,
        action: 'ADMIN_ACTION',
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          actionDetail: 'JSON_DATABASE_IMPORT',
          importedCounts: result.importedCounts
        }
      });
    }

    res.json({
      success: true,
      message: 'JSON database successfully imported and synced to vault_database.json',
      importedCounts: result.importedCounts
    });
  } catch (err: any) {
    res.status(400).json({ success: false, error: 'BadRequest', message: err.message || 'Failed to import JSON database.' });
  }
});

