/**
 * Authentication Endpoints
 * Supports secure session issuance, token revocation, and disabled-user enforcement.
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
import { hashPassword } from '../seed.js';

export const authRouter = express.Router();

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

/**
 * POST /api/auth/session
 * Logs in a user, verifies active status, issues bearer session token
 */
authRouter.post('/session', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const parseResult = LoginSchema.safeParse(req.body);
    if (!parseResult.success) {
      res.status(400).json({ error: 'BadRequest', message: 'Invalid email or password format.' });
      return;
    }

    const { email, password } = parseResult.data;
    const user = await vaultStore.getUserByEmail(email);

    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'unknown';

    if (!user) {
      // Record failed attempt
      await auditEngine.logEvent({
        actorId: 'anonymous',
        actorEmail: email,
        actorRole: 'anonymous',
        action: 'LOGIN_FAILURE',
        outcome: 'FAILURE',
        ip: clientIp,
        userAgent,
        metadata: { reason: 'User not found' }
      });

      res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials.' });
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

      // Track failed attempts for security alerts
      await vaultStore.recordAlert({
        severity: 'MEDIUM',
        type: 'FAILED_LOGIN_ATTEMPT',
        description: `Failed login attempt for account ${user.email}`,
        actorId: user.id,
        actorEmail: user.email,
        ip: clientIp
      });

      res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials.' });
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

    res.json({
      token,
      user: safeUser,
      expiresAt
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Authentication failed.' });
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

    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Logout failed.' });
  }
});

/**
 * GET /api/auth/me
 */
authRouter.get('/me', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
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

  res.json({ user: safeUser });
});
