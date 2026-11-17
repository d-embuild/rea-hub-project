import { Router } from 'express';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import { pool } from '../../db/pool';
import { parseTagCode } from '../../lib/crypto';
import { authenticate, requireRole } from '../../middleware/auth';

export const tagsRouter = Router();

// Brute-force guard on activation attempts (per user).
const activateLimiter = rateLimit({
  windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.user?.id ?? req.ip ?? 'anon',
});

tagsRouter.post('/activate', authenticate(), requireRole('TRAVELER'), activateLimiter, async (req, res, next) => {
  try {
    const { code } = z.object({ code: z.string().min(10).max(60) }).parse(req.body);
    const serial = parseTagCode(code);
    if (!serial) return res.status(400).json({ error: 'INVALID_CODE' });   // bad signature: no DB hit

    // Single atomic statement: only an UNCLAIMED, unowned tag can be bound, and a user can bind only one (unique owner_id).
    const r = await pool.query(
      `update smart_tags set owner_id=$1, status='ACTIVE', activated_at=now()
       where serial_code=$2 and status='UNCLAIMED' and owner_id is null
       returning id, activated_at`,
      [req.user!.id, serial],
    );
    if (!r.rowCount) return res.status(409).json({ error: 'TAG_UNAVAILABLE' }); // claimed, revoked or unknown (same answer on purpose)
    res.status(201).json({ tagId: r.rows[0].id, activatedAt: r.rows[0].activated_at });
  } catch (e: any) {
    if (e.code === '23505') return res.status(409).json({ error: 'USER_ALREADY_HAS_PASS' });
    next(e);
  }
});

tagsRouter.get('/me', authenticate(), requireRole('TRAVELER'), async (req, res, next) => {
  try {
    const r = await pool.query('select id, status, activated_at from smart_tags where owner_id=$1', [req.user!.id]);
    res.json({ tag: r.rows[0] ?? null });
  } catch (e) { next(e); }
});
