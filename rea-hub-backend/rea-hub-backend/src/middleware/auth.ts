import { NextFunction, Request, Response } from 'express';
import { jwtVerify } from 'jose';
import { env } from '../config/env';
import { pool } from '../db/pool';

export interface AuthUser {
  id: string;
  phone?: string;
  aal?: string;
  role?: 'TRAVELER' | 'PARTNER' | 'ADMIN';
  partnerId?: string | null;
}
declare module 'express-serve-static-core' { interface Request { user?: AuthUser } }

const secret = new TextEncoder().encode(env.SUPABASE_JWT_SECRET);

/** Verifies the Supabase JWT. With requireProfile (default) also loads role from our users table. */
export const authenticate = (requireProfile = true) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const h = req.headers.authorization;
      if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'UNAUTHENTICATED' });
      const { payload } = await jwtVerify(h.slice(7), secret, { algorithms: ['HS256'], audience: 'authenticated' });
      const user: AuthUser = { id: String(payload.sub), phone: (payload as any).phone || undefined, aal: (payload as any).aal };
      if (requireProfile) {
        const r = await pool.query('select role, partner_id from users where id = $1', [user.id]);
        if (!r.rowCount) return res.status(403).json({ error: 'PROFILE_REQUIRED' });
        user.role = r.rows[0].role;
        user.partnerId = r.rows[0].partner_id;
      }
      req.user = user;
      next();
    } catch {
      res.status(401).json({ error: 'UNAUTHENTICATED' });
    }
  };

export const requireRole = (...roles: Array<'TRAVELER' | 'PARTNER' | 'ADMIN'>) =>
  (req: Request, res: Response, next: NextFunction) =>
    req.user?.role && roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'FORBIDDEN' });

/** Admin MFA: Supabase marks a session aal2 only after a TOTP challenge was passed. */
export const requireMfa = (req: Request, res: Response, next: NextFunction) =>
  !env.REQUIRE_ADMIN_MFA || req.user?.aal === 'aal2' ? next() : res.status(403).json({ error: 'MFA_REQUIRED' });
