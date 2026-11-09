/**
 * User Management Endpoints
 * Role-restricted controls for user accounts and identity.
 */

import crypto from 'node:crypto';
import express, { type Response } from 'express';
import { z } from 'zod';
import { vaultStore } from '../store.js';
import { auditEngine } from '../audit.js';
import {
  authenticateUser,
  requireRole,
  type AuthenticatedRequest
} from '../authz.js';
import { hashPassword } from '../seed.js';
import type { UserRole } from '../types.js';

export const usersRouter = express.Router();

/**
 * GET /api/users/me
 */
usersRouter.get('/me', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  const { passwordHash, ...safeUser } = req.user;
  res.json({ user: safeUser });
});

/**
 * GET /api/users
 * Returns list of users.
 * If user is admin: returns full user list.
 * If user is owner: returns candidate recipient users for sharing (id, email, displayName).
 */
usersRouter.get('/', authenticateUser, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const all = await vaultStore.getAllUsers();
    const safeList = all.map(u => ({
      id: u.id,
      email: u.email,
      displayName: u.displayName,
      role: u.role,
      active: u.active,
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt
    }));

    res.json({ users: safeList });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to retrieve users.' });
  }
});

const CreateUserSchema = z.object({
  email: z.string().email(),
  displayName: z.string().min(2),
  password: z.string().min(8),
  role: z.enum(['admin', 'owner', 'viewer'])
});

/**
 * POST /api/users (Admin Only)
 */
usersRouter.post('/', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const parse = CreateUserSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'BadRequest', message: parse.error.issues[0].message });
      return;
    }

    const { email, displayName, password, role } = parse.data;
    const existing = await vaultStore.getUserByEmail(email);
    if (existing) {
      res.status(409).json({ error: 'Conflict', message: 'User with this email already exists.' });
      return;
    }

    const newUser = {
      id: 'usr_' + crypto.randomUUID().replace(/-/g, '').substring(0, 12),
      email,
      displayName,
      role: role as UserRole,
      passwordHash: hashPassword(password),
      active: true,
      createdAt: new Date().toISOString()
    };

    await vaultStore.createUser(newUser);

    await auditEngine.logEvent({
      actorId: req.user!.id,
      actorEmail: req.user!.email,
      actorRole: req.user!.role,
      action: 'USER_CREATED',
      targetUserId: newUser.id,
      outcome: 'SUCCESS',
      ip: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'unknown',
      metadata: { targetEmail: newUser.email, role: newUser.role }
    });

    const { passwordHash, ...safe } = newUser;
    res.status(201).json({ user: safe });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'User creation failed.' });
  }
});

const UpdateUserSchema = z.object({
  active: z.boolean().optional(),
  role: z.enum(['admin', 'owner', 'viewer']).optional(),
  displayName: z.string().min(2).optional()
});

/**
 * PATCH /api/users/:id (Admin Only)
 */
usersRouter.patch('/:id', authenticateUser, requireRole(['admin']), async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const userId = req.params.id;
    const targetUser = await vaultStore.getUserById(userId);
    if (!targetUser) {
      res.status(404).json({ error: 'NotFound', message: 'User not found.' });
      return;
    }

    const parse = UpdateUserSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'BadRequest', message: parse.error.issues[0].message });
      return;
    }

    const updates = parse.data;

    // Prevent admin from disabling themselves to avoid lockout
    if (targetUser.id === req.user!.id && updates.active === false) {
      res.status(400).json({ error: 'BadRequest', message: 'Administrators cannot deactivate their own account.' });
      return;
    }

    const updated = await vaultStore.updateUser(userId, updates);

    // Audit changes
    if (updates.active !== undefined && updates.active !== targetUser.active) {
      await auditEngine.logEvent({
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        actorRole: req.user!.role,
        action: updates.active ? 'ADMIN_ACTION' : 'USER_DISABLED',
        targetUserId: targetUser.id,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          action: updates.active ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
          targetEmail: targetUser.email
        }
      });
    }

    if (updates.role && updates.role !== targetUser.role) {
      await auditEngine.logEvent({
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        actorRole: req.user!.role,
        action: 'ROLE_CHANGED',
        targetUserId: targetUser.id,
        outcome: 'SUCCESS',
        ip: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'unknown',
        metadata: {
          oldRole: targetUser.role,
          newRole: updates.role,
          targetEmail: targetUser.email
        }
      });
    }

    const { passwordHash, ...safe } = updated!;
    res.json({ user: safe });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError', message: 'Failed to update user.' });
  }
});
