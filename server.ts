/**
 * TrustVault - Full-Stack Express Server & Vite Dev Middleware
 * Mounts authenticated REST APIs, security headers, rate limiting,
 * and boots the seed data and audit chain.
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { seedInitialData } from './src/server/seed.js';
import { authRouter } from './src/server/routes/auth.js';
import { usersRouter } from './src/server/routes/users.js';
import { documentsRouter } from './src/server/routes/documents.js';
import { permissionsRouter } from './src/server/routes/permissions.js';
import { auditRouter } from './src/server/routes/audit.js';
import { adminRouter } from './src/server/routes/admin.js';
import { pentestRouter } from './src/server/routes/pentest.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Security Headers Middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// JSON and URL-encoded body parsers with strict size limits
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Restricted CORS
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  })
);

// Simple in-memory rate limiter for login protection
const loginAttempts = new Map<string, { count: number; firstAttempt: number }>();
app.use('/api/auth/session', (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (record) {
    if (now - record.firstAttempt > 60000) {
      // Reset window after 1 minute
      loginAttempts.set(ip, { count: 1, firstAttempt: now });
    } else if (record.count >= 20) {
      res.status(429).json({
        error: 'TooManyRequests',
        message: 'Rate limit exceeded for authentication attempts. Please retry in 1 minute.'
      });
      return;
    } else {
      record.count += 1;
    }
  } else {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
  }
  next();
});

// Health check endpoint
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'HEALTHY',
    system: 'TrustVault Enterprise Core',
    timestamp: new Date().toISOString()
  });
});

// Mount API Routers
app.use('/api/auth', authRouter);
app.use('/api/users', usersRouter);
app.use('/api/documents', documentsRouter);
app.use('/api/documents', permissionsRouter);
app.use('/api/audit', auditRouter);
app.use('/api/admin', adminRouter);
app.use('/api/security', pentestRouter);

// Centralized safe error handler (prevents information disclosure)
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('[TrustVault Server Error]', err?.message || err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(err.status || 500).json({
    error: 'InternalError',
    message: process.env.NODE_ENV === 'production' ? 'An unexpected server error occurred.' : err.message
  });
});

async function startServer() {
  // Initialize seed database & sample documents
  await seedInitialData();
  console.log('[TrustVault] Initialized database and cryptographic audit trail.');

  // Check dev mode vs production
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    // Vite Dev Server middleware integration
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
    console.log('[TrustVault] Vite dev middleware attached.');
  } else {
    // Serve production static build
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[TrustVault] Enterprise Vault server listening on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('[TrustVault] Failed to start server:', err);
  process.exit(1);
});

export { app };
