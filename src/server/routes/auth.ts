/**
 * Authentication Endpoints
 * Supports secure session issuance, token revocation, disabled-user enforcement,
 * and verified demo account provisioning.
 */

import crypto from 'node:crypto';
import express, { type Response } from 'express';
import { z } from 'zod';
import { vaultStore } from '../store.js';
import { auditEngine } from '../audit.js';
import {
  authenticateUser,
  activeSessions,
  type AuthenticatedRequest
} from '../authz.js';
import { hashPassword, seedInitialData } from '../seed.js';

export const authRouter = express.Router();

const LoginSchema = z.object({
  email: z.string().min(1, 'Email is required').email('Invalid email address format'),
  password: z.string().min(1, 'Password is required')
});

const DemoSessionSchema = z.object({
  role: z.enum(['admin', 'owner', 'viewer', 'other'])
});

const DEMO_EMAIL_MAP: Record<string, string> = {
  admin: 'admin@trustvault.local',
  owner: 'owner@trustvault.local',
  viewer: 'viewer@trustvault.local',
  other: 'other@trustvault.local'
};

/**
 * POST /api/auth/session
 * Standard authentication endpoint: validates credentials, verifies active status,
 * returns standardized JSON with success, token, role, and user profile.
 */
authRouter.post('/session', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const parseResult = LoginSchema.safeParse(req.body);
    if (!parseResult.success) {
      const issue = parseResult.error.issues[0]?.message || 'Invalid email or password format.';
      res.status(400).json({
        success: false,
        error: 'BadRequest',
        message: issue
      });
      return;
    }

    const { email, password } = parseResult.data;
    const cleanEmail = email.trim().toLowerCase();

    // Ensure database is seeded if fresh
    await seedInitialData();

    const user = await vaultStore.getUserByEmail(cleanEmail);
    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'unknown';

    if (!user) {
      await auditEngine.logEvent({
        actorId: 'anonymous',
        actorEmail: cleanEmail,
        actorRole: 'anonymous',
        action: 'LOGIN_FAILURE',
        outcome: 'FAILURE',
        ip: clientIp,
        userAgent,
        metadata: { reason: 'User not found' }
      });

      res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'Invalid email or password.'
      });
      return;
    }

    // Check account status
    if (!user.active) {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'LOGIN_FAILURE',
        outcome: 'DENIED',
        ip: clientIp,
        userAgent,
        metadata: { reason: 'Account deactivated' }
      });

      res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: 'This account has been deactivated. Please contact an administrator.'
      });
      return;
    }

    // Verify password hash
    const inputHash = hashPassword(password);
    if (inputHash !== user.passwordHash) {
      await auditEngine.logEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'LOGIN_FAILURE',
        outcome: 'FAILURE',
        ip: clientIp,
        userAgent,
        metadata: { reason: 'Password mismatch' }
      });

      await vaultStore.recordAlert({
        severity: 'MEDIUM',
        type: 'FAILED_LOGIN_ATTEMPT',
        description: `Failed login attempt for account ${user.email}`,
        actorId: user.id,
        actorEmail: user.email,
        ip: clientIp
      });

      res.status(401).json({
        success: false,
        error: 'Unauthorized',
        message: 'Invalid email or password.'
      });
      return;
    }

    // Issue session token (24-hour expiration)
    const token = 'tv_tok_' + crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    activeSessions.set(token, { userId: user.id, expiresAt });

    // Update last login
    await vaultStore.updateUser(user.id, { lastLoginAt: new Date().toISOString() });

    // Audit log
    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'LOGIN_SUCCESS',
      outcome: 'SUCCESS',
      ip: clientIp,
      userAgent,
      metadata: { role: user.role }
    });

    const safeUser = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      role: user.role,
      active: user.active,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt
    };

    res.status(200).json({
      success: true,
      token,
      role: user.role,
      user: safeUser,
      expiresAt
    });
  } catch (err: any) {
    console.error('[Auth Error]', err);
    res.status(500).json({
      success: false,
      error: 'InternalServerError',
      message: 'Authentication processing failed.'
    });
  }
});

/**
 * POST /api/auth/demo-session
 * Dedicated verified demo authentication endpoint:
 * Confirms demo account exists in the database, enforces active status,
 * and issues real session token without hardcoded fake responses.
 */
authRouter.post('/demo-session', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const parse = DemoSessionSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({
        success: false,
        error: 'BadRequest',
        message: 'Valid demo role (admin, owner, viewer, other) is required.'
      });
      return;
    }

    const { role } = parse.data;
    const targetEmail = DEMO_EMAIL_MAP[role];

    // Ensure database is initialized with demo accounts
    await seedInitialData();

    const user = await vaultStore.getUserByEmail(targetEmail);
    if (!user) {
      res.status(404).json({
        success: false,
        error: 'NotFound',
        message: `Demo account for role '${role}' (${targetEmail}) not found in database.`
      });
      return;
    }

    // Verify account is active
    if (!user.active) {
      res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: `The demo account '${user.email}' is currently deactivated.`
      });
      return;
    }

    // Issue genuine session token
    const token = 'tv_tok_' + crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    activeSessions.set(token, { userId: user.id, expiresAt });

    await vaultStore.updateUser(user.id, { lastLoginAt: new Date().toISOString() });

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'unknown';

    await auditEngine.logEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'LOGIN_SUCCESS',
      outcome: 'SUCCESS',
      ip: clientIp,
      userAgent,
      metadata: { role: user.role, method: 'DEMO_DIRECT_AUTHENTICATION' }
    });

    const safeUser = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      role: user.role,
      active: user.active,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt
    };

    res.status(200).json({
      success: true,
      token,
      role: user.role,
      user: safeUser,
      expiresAt
    });
  } catch (err: any) {
    console.error('[Demo Auth Error]', err);
    res.status(500).json({
      success: false,
      error: 'InternalServerError',
      message: 'Demo authentication failed.'
    });
  }
});

/**
 * POST /api/auth/logout
 */
authRouter.post('/logout', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7).trim();
      activeSessions.delete(token);
    }

    if (req.user) {
      await auditEngine.logEvent({
        actorId: req.user.id,
        actorEmail: req.user.email,
        actorRole: req.user.role,
        action: 'LOGOUT',
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown'
      });
    }

    res.status(200).json({ success: true, message: 'Logged out successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'InternalServerError', message: 'Logout failed.' });
  }
});

/**
 * GET /api/auth/me
 */
authRouter.get('/me', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized', message: 'Not authenticated.' });
    return;
  }

  const safeUser = {
    id: req.user.id,
    email: req.user.email,
    displayName: req.user.displayName,
    role: req.user.role,
    active: req.user.active,
    createdAt: req.user.createdAt,
    lastLoginAt: req.user.lastLoginAt
  };

  res.status(200).json({ success: true, user: safeUser });
});

/**
 * GET /api/auth/firebase-status
 * Reports exact Firebase configuration status for deployment transparency.
 */
authRouter.get('/firebase-status', (req: express.Request, res: Response) => {
  const hasProjectId = Boolean(process.env.FIREBASE_PROJECT_ID);
  const hasClientEmail = Boolean(process.env.FIREBASE_CLIENT_EMAIL);
  const hasPrivateKey = Boolean(process.env.FIREBASE_PRIVATE_KEY);
  const isFullyConfigured = hasProjectId && hasClientEmail && hasPrivateKey;

  res.status(200).json({
    success: true,
    firebaseConfigured: isFullyConfigured,
    provider: isFullyConfigured ? 'Firebase Authentication & Firestore' : 'TrustVault Zero-Trust Local Vault Provider',
    details: {
      projectId: hasProjectId ? process.env.FIREBASE_PROJECT_ID : 'Not set',
      clientEmail: hasClientEmail ? 'Configured' : 'Missing',
      privateKey: hasPrivateKey ? 'Configured' : 'Missing'
    },
    message: isFullyConfigured
      ? 'Firebase Authentication & Admin SDK are active.'
      : 'Firebase credentials are not set in environment. Running in zero-configuration local encrypted vault mode.'
  });
});
