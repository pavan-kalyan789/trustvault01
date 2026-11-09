/**
 * Demo Seed Data & Initialization Service
 * Provisions non-confidential sample documents, seed accounts,
 * initial permission grants, and verifiable audit events.
 */

import crypto from 'node:crypto';
import { vaultStore } from './store.js';
import { auditEngine } from './audit.js';
import { saveToPrivateStorage } from './storage.js';
import type { User, DocumentRecord, DocumentGrant } from './types.js';

export function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password + '_trustvault_salt_2026').digest('hex');
}

export async function seedInitialData(): Promise<void> {
  const existingUsers = await vaultStore.getAllUsers();
  if (existingUsers.length > 0) {
    return; // Already initialized
  }

  // 1. Create 4 Seed Accounts
  const adminUser: User = {
    id: 'usr_admin_001',
    email: 'admin@trustvault.local',
    displayName: 'Chief Security Officer (Admin)',
    role: 'admin',
    passwordHash: hashPassword('TrustVault2026!Admin'),
    active: true,
    createdAt: new Date('2026-01-10T08:00:00Z').toISOString()
  };

  const ownerUser: User = {
    id: 'usr_owner_001',
    email: 'owner@trustvault.local',
    displayName: 'Sarah Chen (Legal Counsel / Owner)',
    role: 'owner',
    passwordHash: hashPassword('TrustVault2026!Owner'),
    active: true,
    createdAt: new Date('2026-01-10T08:05:00Z').toISOString()
  };

  const viewerUser: User = {
    id: 'usr_viewer_001',
    email: 'viewer@trustvault.local',
    displayName: 'Marcus Vance (Compliance Auditor / Viewer)',
    role: 'viewer',
    passwordHash: hashPassword('TrustVault2026!Viewer'),
    active: true,
    createdAt: new Date('2026-01-10T08:10:00Z').toISOString()
  };

  const otherViewerUser: User = {
    id: 'usr_other_001',
    email: 'other@trustvault.local',
    displayName: 'Alex Morgan (External Contractor / Viewer)',
    role: 'viewer',
    passwordHash: hashPassword('TrustVault2026!Other'),
    active: true,
    createdAt: new Date('2026-01-10T08:15:00Z').toISOString()
  };

  await vaultStore.createUser(adminUser);
  await vaultStore.createUser(ownerUser);
  await vaultStore.createUser(viewerUser);
  await vaultStore.createUser(otherViewerUser);

  // 2. Create Physical Sample Files with genuine Magic Bytes
  // Valid PDF header and minimal structure
  const pdfBuffer = Buffer.from(
    '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 55 >>\nstream\nBT /F1 12 Tf 100 700 Td (TrustVault Verified Enterprise Document) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000117 00000 n \n0000000210 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n315\n%%EOF\n',
    'utf-8'
  );

  // Valid text buffer
  const txtBuffer = Buffer.from(
    'TRUSTVAULT SECURE ENTERPRISE DOCUMENT\n===================================\nDocument ID: SEC-2026-001\nClassification: RESTRICTED\nRetention: 7 Years\n\nThis document is protected under TrustVault enterprise access policies.',
    'utf-8'
  );

  // Valid zip container buffer (ZIP magic bytes 50 4B 03 04)
  const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00]);
  const docxPayload = Buffer.concat([zipHeader, Buffer.from('word/document.xml - TrustVault Specification')]);

  const storageKeyPdf1 = await saveToPrivateStorage(pdfBuffer);
  const storageKeyPdf2 = await saveToPrivateStorage(pdfBuffer);
  const storageKeyTxt = await saveToPrivateStorage(txtBuffer);
  const storageKeyDocx = await saveToPrivateStorage(docxPayload);

  // 3. Create Sample Documents
  const doc1: DocumentRecord = {
    id: 'doc_msa_2026',
    name: 'Master Services Agreement 2026',
    description: 'Bilateral SaaS enterprise SLA and mutual NDA terms.',
    originalFilename: 'Master_Services_Agreement_2026.pdf',
    ownerId: ownerUser.id,
    ownerEmail: ownerUser.email,
    category: 'Contracts',
    mimeType: 'application/pdf',
    size: pdfBuffer.length,
    sha256Hash: crypto.createHash('sha256').update(pdfBuffer).digest('hex'),
    storageKey: storageKeyPdf1,
    createdAt: new Date('2026-01-15T10:00:00Z').toISOString(),
    updatedAt: new Date('2026-01-15T10:00:00Z').toISOString(),
    version: 1,
    isDeleted: false,
    retentionStatus: 'active'
  };

  const doc2: DocumentRecord = {
    id: 'doc_audit_q3',
    name: 'Q3 Financial Audit & Ledger Reconciliation',
    description: 'Internal financial audit report and variance analysis. Strictly confidential.',
    originalFilename: 'Q3_Financial_Audit_Report.pdf',
    ownerId: ownerUser.id,
    ownerEmail: ownerUser.email,
    category: 'Confidential',
    mimeType: 'application/pdf',
    size: pdfBuffer.length,
    sha256Hash: crypto.createHash('sha256').update(pdfBuffer).digest('hex'),
    storageKey: storageKeyPdf2,
    createdAt: new Date('2026-02-01T14:30:00Z').toISOString(),
    updatedAt: new Date('2026-02-01T14:30:00Z').toISOString(),
    version: 1,
    isDeleted: false,
    retentionStatus: 'active'
  };

  const doc3: DocumentRecord = {
    id: 'doc_handbook_v4',
    name: 'Employee Security Handbook v4',
    description: 'Information security guidelines and acceptable use policy.',
    originalFilename: 'Employee_Handbook_v4.txt',
    ownerId: ownerUser.id,
    ownerEmail: ownerUser.email,
    category: 'HR',
    mimeType: 'text/plain',
    size: txtBuffer.length,
    sha256Hash: crypto.createHash('sha256').update(txtBuffer).digest('hex'),
    storageKey: storageKeyTxt,
    createdAt: new Date('2026-02-10T09:15:00Z').toISOString(),
    updatedAt: new Date('2026-02-10T09:15:00Z').toISOString(),
    version: 1,
    isDeleted: false,
    retentionStatus: 'active'
  };

  const doc4: DocumentRecord = {
    id: 'doc_arch_spec',
    name: 'Zero-Trust Architecture Blueprint',
    description: 'Network micro-segmentation and KMS specification.',
    originalFilename: 'Security_Architecture_Blueprint.docx',
    ownerId: ownerUser.id,
    ownerEmail: ownerUser.email,
    category: 'Technical',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    size: docxPayload.length,
    sha256Hash: crypto.createHash('sha256').update(docxPayload).digest('hex'),
    storageKey: storageKeyDocx,
    createdAt: new Date('2026-02-20T11:45:00Z').toISOString(),
    updatedAt: new Date('2026-02-20T11:45:00Z').toISOString(),
    version: 1,
    isDeleted: false,
    retentionStatus: 'active'
  };

  await vaultStore.createDocument(doc1);
  await vaultStore.createDocument(doc2);
  await vaultStore.createDocument(doc3);
  await vaultStore.createDocument(doc4);

  // 4. Create Initial Permission Grants
  // Viewer has explicit READ access to doc1 (Master Services Agreement)
  const grant1: DocumentGrant = {
    id: 'grnt_001_viewer_msa',
    documentId: doc1.id,
    grantorId: ownerUser.id,
    grantorEmail: ownerUser.email,
    granteeId: viewerUser.id,
    granteeEmail: viewerUser.email,
    permissionLevel: 'READ',
    createdAt: new Date('2026-01-16T11:00:00Z').toISOString(),
    expiresAt: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
    isActive: true
  };
  await vaultStore.createGrant(grant1);

  // 5. Seed Tamper-Evident Audit Chain
  await auditEngine.logEvent({
    actorId: adminUser.id,
    actorEmail: adminUser.email,
    actorRole: 'admin',
    action: 'USER_CREATED',
    targetUserId: ownerUser.id,
    outcome: 'SUCCESS',
    metadata: { note: 'Initial system provisioning' }
  });

  await auditEngine.logEvent({
    actorId: ownerUser.id,
    actorEmail: ownerUser.email,
    actorRole: 'owner',
    action: 'DOCUMENT_UPLOAD',
    documentId: doc1.id,
    outcome: 'SUCCESS',
    metadata: { filename: doc1.originalFilename, size: doc1.size, hash: doc1.sha256Hash }
  });

  await auditEngine.logEvent({
    actorId: ownerUser.id,
    actorEmail: ownerUser.email,
    actorRole: 'owner',
    action: 'DOCUMENT_UPLOAD',
    documentId: doc2.id,
    outcome: 'SUCCESS',
    metadata: { filename: doc2.originalFilename, size: doc2.size, category: 'Confidential' }
  });

  await auditEngine.logEvent({
    actorId: ownerUser.id,
    actorEmail: ownerUser.email,
    actorRole: 'owner',
    action: 'PERMISSION_GRANTED',
    documentId: doc1.id,
    targetUserId: viewerUser.id,
    outcome: 'SUCCESS',
    metadata: { level: 'READ', grantee: viewerUser.email }
  });

  // Create initial anchored checkpoint
  auditEngine.createCheckpoint();
}
