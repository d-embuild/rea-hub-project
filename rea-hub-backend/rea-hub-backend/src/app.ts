import { randomUUID } from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { ZodError } from 'zod';
import { env } from './config/env';
import { authRouter } from './modules/auth/auth.routes';
import { tagsRouter } from './modules/tags/tags.routes';
import { qrRouter } from './modules/qr/qr.routes';
import { redemptionsRouter } from './modules/redemptions/redemptions.routes';
import { directoryRouter } from './modules/directory/directory.routes';
import { activityRouter } from './modules/activity/activity.routes';
import { adminRouter } from './modules/admin/admin.routes';

export const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                       // behind Nginx (TLS terminated there)
app.use((req, res, next) => {                    // correlation id on every request/response/error
  (req as any).id = randomUUID();
  res.setHeader('X-Request-Id', (req as any).id);
  next();
});
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'no-referrer' },
  frameguard: { action: 'deny' },
  contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
}));
app.use(cors({ origin: env.CORS_ORIGINS.split(',').filter(Boolean), credentials: false }));
app.use(express.json({ limit: '20kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

app.use((req, res, next) => {                    // reject plain HTTP in production
  if (env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') return res.status(426).json({ error: 'HTTPS_REQUIRED' });
  next();
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));
app.use('/v1/auth', authRouter);
app.use('/v1/tags', tagsRouter);
app.use('/v1/qr', qrRouter);
app.use('/v1/redemptions', redemptionsRouter);
app.use('/v1/partners', directoryRouter);
app.use('/v1/heartbeat', activityRouter);
app.use('/v1/admin', adminRouter);

app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  const requestId = (req as any).id;
  if (err instanceof ZodError) return res.status(400).json({ error: 'VALIDATION', issues: err.issues, requestId });
  console.error(requestId, err);                 // details stay in server logs only
  res.status(500).json({ error: 'INTERNAL', requestId });
});
