import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { pool } from '../../db/pool';
import { signQr, QR_TTL_SECONDS } from '../../lib/crypto';
import { authenticate, requireRole } from '../../middleware/auth';

export const qrRouter = Router();

// Flutter calls this every ~40s; token lives 45s. Stateless: nothing stored server-side.
qrRouter.get('/', authenticate(), requireRole('TRAVELER'),
  rateLimit({ windowMs: 60_000, limit: 20, keyGenerator: (r) => r.user?.id ?? r.ip ?? 'anon' }),
  async (req, res, next) => {
    try {
      const t = await pool.query(`select id from smart_tags where owner_id=$1 and status='ACTIVE'`, [req.user!.id]);
      if (!t.rowCount) return res.status(404).json({ error: 'NO_ACTIVE_PASS' });
      const { token, payload } = signQr(t.rows[0].id);
      res.set('Cache-Control', 'no-store').json({ token, expiresAt: payload.exp, ttl: QR_TTL_SECONDS });
    } catch (e) { next(e); }
  });
