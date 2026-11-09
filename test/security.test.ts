/**
 * TrustVault Security Integration Test Suite
 * Automated tests for IDOR prevention, immediate revocation,
 * audit chain integrity, file validation, and mutation testing.
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { seedInitialData } from '../src/server/seed.js';
import { vaultStore } from '../src/server/store.js';
import { auditEngine } from '../src/server/audit.js';
import { setMutationTestBypass, canReadDocument } from '../src/server/authz.js';
import { validateUploadedFile } from '../src/server/storage.js';
import { authRouter } from '../src/server/routes/auth.js';
import { usersRouter } from '../src/server/routes/users.js';
import { documentsRouter } from '../src/server/routes/documents.js';
import { permissionsRouter } from '../src/server/routes/permissions.js';
import { auditRouter } from '../src/server/routes/audit.js';
import { adminRouter } from '../src/server/routes/admin.js';

// Setup test app instance
const testApp = express();
testApp.use(express.json());
testApp.use('/api/auth', authRouter);
testApp.use('/api/users', usersRouter);
testApp.use('/api/documents', documentsRouter);
testApp.use('/api/documents', permissionsRouter);
testApp.use('/api/audit', auditRouter);
testApp.use('/api/admin', adminRouter);

let adminToken: string;
let ownerToken: string;
let viewerToken: string;
let otherToken: string;

let confidentialDocId: string;
let sharedDocId: string;

beforeAll(async () => {
  await seedInitialData();

  // Obtain tokens for all 4 roles
  const resAdmin = await request(testApp)
    .post('/api/auth/session')
    .send({ email: 'admin@trustvault.local', password: 'TrustVault2026!Admin' });
  adminToken = resAdmin.body.token;

  const resOwner = await request(testApp)
    .post('/api/auth/session')
    .send({ email: 'owner@trustvault.local', password: 'TrustVault2026!Owner' });
  ownerToken = resOwner.body.token;

  const resViewer = await request(testApp)
    .post('/api/auth/session')
    .send({ email: 'viewer@trustvault.local', password: 'TrustVault2026!Viewer' });
  viewerToken = resViewer.body.token;

  const resOther = await request(testApp)
    .post('/api/auth/session')
    .send({ email: 'other@trustvault.local', password: 'TrustVault2026!Other' });
  otherToken = resOther.body.token;

  // Retrieve document IDs
  const ownerDocs = await request(testApp)
    .get('/api/documents')
    .set('Authorization', `Bearer ${ownerToken}`);

  const confDoc = ownerDocs.body.documents.find((d: any) => d.category === 'Confidential');
  confidentialDocId = confDoc.id;

  const shDoc = ownerDocs.body.documents.find((d: any) => d.category === 'Contracts');
  sharedDocId = shDoc.id;
});

afterEach(() => {
  // Always guarantee mutation test bypass is disabled
  setMutationTestBypass(false);
});

describe('1. Authentication & Boundary Protection', () => {
  it('rejects unauthenticated requests with 401', async () => {
    const res = await request(testApp).get('/api/documents');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('rejects forged/invalid tokens with 401', async () => {
    const res = await request(testApp)
      .get('/api/documents')
      .set('Authorization', 'Bearer invalid_forged_token_xyz');
    expect(res.status).toBe(401);
  });

  it('prevents viewer from accessing admin routes (vertical privilege escalation defense)', async () => {
    const res = await request(testApp)
      .get('/api/admin/dashboard')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Forbidden');
  });

  it('immediately blocks deactivated accounts on protected endpoints', async () => {
    const otherUser = await vaultStore.getUserByEmail('other@trustvault.local');
    await vaultStore.updateUser(otherUser!.id, { active: false });

    const res = await request(testApp)
      .get('/api/documents')
      .set('Authorization', `Bearer ${otherToken}`);

    // Re-enable account
    await vaultStore.updateUser(otherUser!.id, { active: true });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Forbidden');
  });
});

describe('2. Anti-IDOR & Document Isolation', () => {
  it('prevents unauthorized viewer from reading confidential document metadata (returns 404)', async () => {
    const res = await request(testApp)
      .get(`/api/documents/${confidentialDocId}`)
      .set('Authorization', `Bearer ${otherToken}`);
    expect(res.status).toBe(404);
  });

  it('prevents unauthorized viewer from downloading confidential document (returns 404)', async () => {
    const res = await request(testApp)
      .get(`/api/documents/${confidentialDocId}/download`)
      .set('Authorization', `Bearer ${otherToken}`);
    expect(res.status).toBe(404);
  });

  it('ADMINISTRATIVE SEPARATION: Administrator cannot automatically download confidential files without grant', async () => {
    const res = await request(testApp)
      .get(`/api/documents/${confidentialDocId}/download`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });

  it('search endpoint strictly isolates results and does not disclose unauthorized document metadata', async () => {
    const res = await request(testApp)
      .get('/api/documents')
      .set('Authorization', `Bearer ${otherToken}`);

    expect(res.status).toBe(200);
    const hasConfidential = res.body.documents.some((d: any) => d.id === confidentialDocId);
    expect(hasConfidential).toBe(false);
  });
});

describe('3. Permission Enforcement & Immediate Revocation', () => {
  it('allows authorized viewer to download shared document', async () => {
    const res = await request(testApp)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.header['cache-control']).toBe('no-store, private');
    expect(res.header['x-content-type-options']).toBe('nosniff');
  });

  it('viewer with READ permission cannot edit or delete document', async () => {
    const editRes = await request(testApp)
      .patch(`/api/documents/${sharedDocId}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ name: 'Hacked Name' });

    expect(editRes.status).toBe(404); // 404 anti-disclosure

    const deleteRes = await request(testApp)
      .delete(`/api/documents/${sharedDocId}`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(deleteRes.status).toBe(404);
  });

  it('IMMEDIATE ACCESS REVOCATION: Revoking permission blocks subsequent downloads instantly', async () => {
    // 1. Grant otherViewer access to sharedDoc
    const grantRes = await request(testApp)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ granteeEmail: 'other@trustvault.local', permissionLevel: 'READ' });

    expect(grantRes.status).toBe(201);
    const grantId = grantRes.body.grant.id;

    // 2. Download succeeds
    const download1 = await request(testApp)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${otherToken}`);
    expect(download1.status).toBe(200);

    // 3. Revoke permission
    const revokeRes = await request(testApp)
      .delete(`/api/documents/${sharedDocId}/permissions/${grantId}`)
      .set('Authorization', `Bearer ${ownerToken}`);
    expect(revokeRes.status).toBe(200);

    // 4. Download immediately fails!
    const download2 = await request(testApp)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${otherToken}`);
    expect(download2.status).toBe(404);
  });

  it('disallows document owner from granting permissions to themselves', async () => {
    const res = await request(testApp)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ granteeEmail: 'owner@trustvault.local', permissionLevel: 'READ' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('BadRequest');
  });
});

describe('4. File Validation & Private Storage Hardening', () => {
  it('detects and rejects MIME spoofing (text disguised as .pdf)', () => {
    const spoofed = Buffer.from('Plain text pretending to be PDF');
    const result = validateUploadedFile(spoofed, 'report.pdf', 'application/pdf');
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('MIME Spoofing');
  });

  it('strictly rejects executable file uploads', () => {
    const exe = Buffer.from([0x4d, 0x5a, 0x90, 0x00]); // MZ
    const result = validateUploadedFile(exe, 'payload.exe', 'application/octet-stream');
    expect(result.isValid).toBe(false);
  });

  it('rejects path traversal in filename', () => {
    const validTxt = Buffer.from('Sample valid content');
    const result = validateUploadedFile(validTxt, '../../../etc/passwd.txt', 'text/plain');
    expect(result.isValid).toBe(false);
  });

  it('rejects oversized files (>10MB)', () => {
    const big = Buffer.alloc(11 * 1024 * 1024);
    const result = validateUploadedFile(big, 'big.pdf', 'application/pdf');
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('exceeds the 10 MB limit');
  });
});

describe('5. Cryptographic Audit Trail & Chain Verification', () => {
  it('verifies the intact cryptographic HMAC-SHA256 hash chain', async () => {
    const verifyRes = await request(testApp)
      .post('/api/audit/verify')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.verification.isValid).toBe(true);
    expect(verifyRes.body.verification.totalEvents).toBeGreaterThan(0);
  });

  it('detects tampering when an audit event is modified', () => {
    const events = (auditEngine as any).events;
    if (events.length > 2) {
      const originalAction = events[1].action;
      // Tamper
      events[1].action = 'ADMIN_ACTION';
      const result = auditEngine.verifyAuditChain();
      expect(result.isValid).toBe(false);
      // Restore
      events[1].action = originalAction;
    }
  });

  it('preserves valid hash chain across concurrent writes', async () => {
    const writes = Array.from({ length: 6 }).map((_, i) =>
      auditEngine.logEvent({
        actorId: 'usr_test',
        actorEmail: 'test@vault.local',
        actorRole: 'owner',
        action: 'DOCUMENT_VIEW',
        outcome: 'SUCCESS',
        metadata: { batchIndex: i }
      })
    );
    await Promise.all(writes);
    const result = auditEngine.verifyAuditChain();
    expect(result.isValid).toBe(true);
  });
});

describe('6. Mutation Testing (Verification of Central Authorization Check)', () => {
  it('proves that removing/bypassing central authorization causes security checks to fail, and restoring passes', async () => {
    const otherUser = await vaultStore.getUserByEmail('other@trustvault.local');
    const confDoc = await vaultStore.getDocumentById(confidentialDocId);

    // 1. Initial State: otherUser CANNOT read confidential document
    const initialCheck = await canReadDocument(otherUser!, confDoc!);
    expect(initialCheck).toBe(false);

    // 2. MUTATION: Temporarily bypass authorization check
    setMutationTestBypass(true);

    // When bypassed, canReadDocument incorrectly returns true
    const mutatedCheck = await canReadDocument(otherUser!, confDoc!);
    expect(mutatedCheck).toBe(true);

    // 3. RESTORE authorization check immediately
    setMutationTestBypass(false);

    // Verify it is restored and test passes again
    const restoredCheck = await canReadDocument(otherUser!, confDoc!);
    expect(restoredCheck).toBe(false);
  });
});
