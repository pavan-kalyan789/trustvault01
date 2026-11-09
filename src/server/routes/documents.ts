/**
 * Document Management API Router
 * Comprehensive document lifecycle with IDOR defense, magic-byte validation,
 * private storage streaming, and version tracking.
 */

import crypto from 'node:crypto';
import express, { type Response } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { vaultStore } from '../store.js';
import { auditEngine } from '../audit.js';
import {
  authenticateUser,
  requireRole,
  requireDocumentAccess,
  canReadDocument,
  canEditDocument,
  canDeleteDocument,
  type AuthenticatedRequest
} from '../authz.js';
import {
  validateUploadedFile,
  saveToPrivateStorage,
  getFromPrivateStorage,
  MAX_UPLOAD_SIZE_BYTES
} from '../storage.js';
import type { DocumentCategory, DocumentRecord, DocumentVersion } from '../types.js';

export const documentsRouter = express.Router();

// Memory storage for file inspection before persisting
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_UPLOAD_SIZE_BYTES + 1024 // Allow buffer to trigger custom validation
  }
});

/**
 * GET /api/documents
 * Secure Search & Listing: strictly returns only authorized documents
 */
documentsRouter.get('/', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const query = req.query.q as string | undefined;
    const category = req.query.category as string | undefined;
    const adminMode = req.query.adminView === 'true' && user.role === 'admin';

    let docs: DocumentRecord[];

    if (adminMode) {
      // Governance metadata view for administrator
      const allDocs = await vaultStore.getAdminDocumentMetadataList();
      docs = allDocs.filter(d => {
        if (category && category !== 'ALL' && d.category !== category) return false;
        if (query) {
          const q = query.toLowerCase();
          return d.name.toLowerCase().includes(q) || d.originalFilename.toLowerCase().includes(q);
        }
        return true;
      });
    } else {
      // Standard user & viewer: returns ONLY documents user owns or has explicit active grant for!
      docs = await vaultStore.searchAccessibleDocuments(user.id, {
        query,
        category
      });
    }

    res.json({ documents: docs });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to search documents.' });
  }
});

const DocumentMetadataSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(1000).optional(),
  category: z.enum([
    'Contracts',
    'Finance',
    'HR',
    'Legal',
    'Technical',
    'Audit',
    'Confidential',
    'General'
  ])
});

/**
 * POST /api/documents
 * Secure Upload: Enforces file validation, magic bytes, and private storage
 */
documentsRouter.post(
  '/',
  authenticateUser,
  requireRole(['admin', 'owner']),
  upload.single('file'),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const user = req.user!;

      if (!req.file) {
        res.status(400).json({ error: 'BadRequest', message: 'Document file is required.' });
        return;
      }

      const parseMeta = DocumentMetadataSchema.safeParse(req.body);
      if (!parseMeta.success) {
        res.status(400).json({ error: 'BadRequest', message: parseMeta.error.issues[0].message });
        return;
      }

      const { name, description, category } = parseMeta.data;

      // File validation: magic bytes, MIME spoofing check, dangerous extensions, path traversal
      const validation = validateUploadedFile(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype
      );

      if (!validation.isValid) {
        // Record denied upload attempt
        await auditEngine.logEvent({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: 'ACCESS_DENIED',
          outcome: 'DENIED',
          ip: req.ip || '127.0.0.1',
          userAgent: req.headers['user-agent'] || 'unknown',
          metadata: {
            reason: 'File validation failed',
            error: validation.error,
            filename: req.file.originalname
          }
        });

        res.status(400).json({
          error: 'ValidationFailed',
          message: validation.error || 'Invalid file format.'
        });
        return;
      }

      // Store file in private object storage using random UUID key
      const storageKey = await saveToPrivateStorage(req.file.buffer);

      const docId = 'doc_' + crypto.randomUUID().replace(/-/g, '').substring(0, 16);
      const now = new Date().toISOString();

      const newDoc: DocumentRecord = {
        id: docId,
        name,
        description: description || '',
        originalFilename: validation.sanitizedFilename!,
        ownerId: user.id,
        ownerEmail: user.email,
        category: category as DocumentCategory,
        mimeType: validation.detectedMimeType!,
        size: req.file.buffer.length,
        sha256Hash: validation.sha256Hash!,
        storageKey,
        createdAt: now,
        updatedAt: now,
        version: 1,
        isDeleted: false,
        retentionStatus: 'active'
      };

      await vaultStore.createDocument(newDoc);

      // Create initial version record
      const initialVersion: DocumentVersion = {
        id: 'ver_' + crypto.randomUUID(),
        documentId: docId,
        versionNumber: 1,
        storageKey,
        sha256Hash: validation.sha256Hash!,
        size: req.file.buffer.length,
        originalFilename: validation.sanitizedFilename!,
        mimeType: validation.detectedMimeType!,
        createdBy: user.id,
        createdByEmail: user.email,
        createdAt: now,
        changeDescription: 'Initial document upload'
      };
      await vaultStore.createVersion(initialVersion);

      // Audit log
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'DOCUMENT_UPLOAD',
        documentId: docId,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          filename: newDoc.originalFilename,
          size: newDoc.size,
          sha256: newDoc.sha256Hash,
          category: newDoc.category
        }
      });

      res.status(201).json({ document: newDoc });
    } catch (err) {
      res.status(500).json({ error: 'InternalServerError', message: 'Failed to process document upload.' });
    }
  }
);

/**
 * GET /api/documents/:id
 * Retrieve document metadata (checks READ access or Admin metadata inspection)
 */
documentsRouter.get('/:id', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const doc = await vaultStore.getDocumentById(req.params.id);

    if (!doc) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    const canRead = await canReadDocument(user, doc);

    // If not readable and user is not admin
    if (!canRead && user.role !== 'admin') {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { attemptedAction: 'VIEW_METADATA', documentId: doc.id }
      });

      res.status(404).json({ error: 'NotFound', message: 'Document not found or access denied.' });
      return;
    }

    res.json({ document: doc, userCanDownload: canRead });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to fetch document metadata.' });
  }
});

const UpdateMetadataSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  description: z.string().max(1000).optional(),
  category: z
    .enum(['Contracts', 'Finance', 'HR', 'Legal', 'Technical', 'Audit', 'Confidential', 'General'])
    .optional()
});

/**
 * PATCH /api/documents/:id
 * Edit metadata - requires EDIT permission or OWNER
 */
documentsRouter.patch(
  '/:id',
  authenticateUser,
  requireDocumentAccess('EDIT'),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const user = req.user!;
      const doc = await vaultStore.getDocumentById(req.params.id);
      if (!doc) {
        res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
        return;
      }

      const parse = UpdateMetadataSchema.safeParse(req.body);
      if (!parse.success) {
        res.status(400).json({ error: 'BadRequest', message: parse.error.issues[0].message });
        return;
      }

      const updated = await vaultStore.updateDocument(doc.id, parse.data);

      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'DOCUMENT_UPDATE',
        documentId: doc.id,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { updates: parse.data }
      });

      res.json({ document: updated });
    } catch (err) {
      res.status(500).json({ error: 'InternalServerError', message: 'Failed to update document.' });
    }
  }
);

/**
 * GET /api/documents/:id/download
 * Streaming Document Download:
 * Re-evaluates database authorization on EVERY single request!
 * Strictly prevents Admin bypass if admin lacks explicit grant.
 */
documentsRouter.get('/:id/download', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const docId = req.params.id;
    const doc = await vaultStore.getDocumentById(docId);

    if (!doc || doc.isDeleted) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    // CURRENT DATABASE AUTHORIZATION CHECK
    const authorized = await canReadDocument(user, doc);

    if (!authorized) {
      // Record denied download event in tamper-evident audit trail
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          attemptedAction: 'DOWNLOAD',
          documentName: doc.name,
          category: doc.category
        }
      });

      // Security alert for admin attempting download or unauthorized viewer access
      await vaultStore.recordAlert({
        severity: user.role === 'admin' ? 'HIGH' : 'MEDIUM',
        type: 'UNAUTHORIZED_DOWNLOAD_ATTEMPT',
        description: `Blocked download attempt on '${doc.name}' (${doc.id}) by ${user.email} (${user.role})`,
        actorId: user.id,
        actorEmail: user.email,
        documentId: doc.id,
        ip: req.ip || '127.0.0.1'
      });

      res.status(404).json({
        error: 'NotFound',
        message: 'Document not found or access denied.'
      });
      return;
    }

    // Retrieve file buffer from private storage
    const fileBuffer = await getFromPrivateStorage(doc.storageKey);
    if (!fileBuffer) {
      res.status(404).json({ error: 'NotFound', message: 'Storage object missing.' });
      return;
    }

    // Record authorized download audit event
    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'DOCUMENT_DOWNLOAD',
      documentId: doc.id,
      outcome: 'SUCCESS',
      ip: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'unknown',
      metadata: {
        filename: doc.originalFilename,
        size: doc.size,
        version: doc.version
      }
    });

    // Stream download with strict security headers
    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.originalFilename)}"`);
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Pragma', 'no-cache');

    res.send(fileBuffer);
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Download failed.' });
  }
});

/**
 * GET /api/documents/:id/preview
 * Streaming Preview (inline) with identical authorization check
 */
documentsRouter.get('/:id/preview', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    const docId = req.params.id;
    const doc = await vaultStore.getDocumentById(docId);

    if (!doc || doc.isDeleted) {
      res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
      return;
    }

    const authorized = await canReadDocument(user, doc);
    if (!authorized) {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'ACCESS_DENIED',
        documentId: doc.id,
        outcome: 'DENIED',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { attemptedAction: 'PREVIEW', documentName: doc.name }
      });

      res.status(404).json({ error: 'NotFound', message: 'Document not found or access denied.' });
      return;
    }

    const fileBuffer = await getFromPrivateStorage(doc.storageKey);
    if (!fileBuffer) {
      res.status(404).json({ error: 'NotFound', message: 'Storage object missing.' });
      return;
    }

    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'DOCUMENT_VIEW',
      documentId: doc.id,
      outcome: 'SUCCESS',
      ip: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'unknown',
      metadata: { filename: doc.originalFilename, preview: true }
    });

    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(doc.originalFilename)}"`);
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    res.send(fileBuffer);
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Preview failed.' });
  }
});

/**
 * DELETE /api/documents/:id
 * Soft-delete. Only OWNER can delete!
 */
documentsRouter.delete(
  '/:id',
  authenticateUser,
  requireDocumentAccess('OWNER'),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const user = req.user!;
      const doc = await vaultStore.getDocumentById(req.params.id);
      if (!doc) {
        res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
        return;
      }

      await vaultStore.deleteDocument(doc.id);

      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'DOCUMENT_DELETE',
        documentId: doc.id,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { documentName: doc.name }
      });

      res.json({ success: true, message: 'Document successfully soft-deleted.' });
    } catch (err) {
      res.status(500).json({ error: 'InternalServerError', message: 'Failed to delete document.' });
    }
  }
);

/**
 * POST /api/documents/:id/restore
 * Restore soft-deleted document. Only OWNER can restore!
 */
documentsRouter.post(
  '/:id/restore',
  authenticateUser,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const user = req.user!;
      const doc = await vaultStore.getDocumentById(req.params.id);
      if (!doc) {
        res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
        return;
      }

      if (!canDeleteDocument(user, doc)) {
        res.status(403).json({ error: 'Forbidden', message: 'Only the document owner can restore this document.' });
        return;
      }

      await vaultStore.restoreDocument(doc.id);

      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'DOCUMENT_RESTORE',
        documentId: doc.id,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: { documentName: doc.name }
      });

      res.json({ success: true, message: 'Document restored.' });
    } catch (err) {
      res.status(500).json({ error: 'InternalServerError', message: 'Failed to restore document.' });
    }
  }
);

/**
 * GET /api/documents/:id/versions
 * List version history
 */
documentsRouter.get(
  '/:id/versions',
  authenticateUser,
  requireDocumentAccess('READ'),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const versions = await vaultStore.getVersionsForDocument(req.params.id);
      res.json({ versions });
    } catch (err) {
      res.status(500).json({ error: 'InternalServerError', message: 'Failed to fetch versions.' });
    }
  }
);

/**
 * POST /api/documents/:id/versions
 * Upload new version (Requires EDIT or OWNER)
 */
documentsRouter.post(
  '/:id/versions',
  authenticateUser,
  requireDocumentAccess('EDIT'),
  upload.single('file'),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const user = req.user!;
      const doc = await vaultStore.getDocumentById(req.params.id);
      if (!doc) {
        res.status(404).json({ error: 'NotFound', message: 'Document not found.' });
        return;
      }

      if (!req.file) {
        res.status(400).json({ error: 'BadRequest', message: 'Replacement file required.' });
        return;
      }

      const changeDescription = (req.body.changeDescription as string) || 'New version upload';

      const validation = validateUploadedFile(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype
      );

      if (!validation.isValid) {
        res.status(400).json({ error: 'ValidationFailed', message: validation.error });
        return;
      }

      const newStorageKey = await saveToPrivateStorage(req.file.buffer);
      const newVersionNum = doc.version + 1;
      const now = new Date().toISOString();

      const versionRecord: DocumentVersion = {
        id: 'ver_' + crypto.randomUUID(),
        documentId: doc.id,
        versionNumber: newVersionNum,
        storageKey: newStorageKey,
        sha256Hash: validation.sha256Hash!,
        size: req.file.buffer.length,
        originalFilename: validation.sanitizedFilename!,
        mimeType: validation.detectedMimeType!,
        createdBy: user.id,
        createdByEmail: user.email,
        createdAt: now,
        changeDescription
      };

      await vaultStore.createVersion(versionRecord);

      // Update primary document pointer
      await vaultStore.updateDocument(doc.id, {
        version: newVersionNum,
        storageKey: newStorageKey,
        sha256Hash: validation.sha256Hash!,
        size: req.file.buffer.length,
        originalFilename: validation.sanitizedFilename!,
        mimeType: validation.detectedMimeType!
      });

      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'DOCUMENT_VERSION_CREATED',
        documentId: doc.id,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          newVersion: newVersionNum,
          filename: validation.sanitizedFilename,
          sha256: validation.sha256Hash
        }
      });

      res.status(201).json({ version: versionRecord });
    } catch (err) {
      res.status(500).json({ error: 'InternalServerError', message: 'Version upload failed.' });
    }
  }
);
