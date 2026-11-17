import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { pool } from '../../db/pool';
import { authenticate } from '../../middleware/auth';

export const activityRouter = Router();

// App calls this every ~60s while foregrounded. Powers "online now", DAU and MAU.
activityRouter.post('/', authenticate(),
  rateLimit({ windowMs: 60_000, limit: 6, keyGenerator: (r) => r.user?.id ?? r.ip ?? 'anon' }),
  async (req, res, next) => {
    try {
      await Promise.all([
        pool.query(`insert into user_heartbeats (user_id, last_seen_at) values ($1, now())
                    on conflict (user_id) do update set last_seen_at = now()`, [req.user!.id]),
        pool.query(`insert into user_activity_daily (user_id, day) values ($1, (now() at time zone 'Asia/Manila')::date)
                    on conflict do nothing`, [req.user!.id]),
      ]);
      res.status(204).end();
    } catch (e) { next(e); }
  });
