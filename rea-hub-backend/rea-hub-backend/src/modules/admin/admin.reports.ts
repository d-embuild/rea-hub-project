import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool';

export const reportsRouter = Router();   // mounted under adminRouter (ADMIN + MFA already enforced)
const MNL = `(now() at time zone 'Asia/Manila')::date`;

reportsRouter.get('/analytics/summary', async (_req, res, next) => {
  try {
    const [online, dau, mau, tags, today, month, top] = await Promise.all([
      pool.query(`select count(*)::int n from user_heartbeats where last_seen_at > now() - interval '5 minutes'`),
      pool.query(`select count(*)::int n from user_activity_daily where day = ${MNL}`),
      pool.query(`select count(distinct user_id)::int n from user_activity_daily where day > ${MNL} - 30`),   // rolling 30 days
      pool.query(`select count(*)::int n from smart_tags where status='ACTIVE'`),
      pool.query(`select count(*)::int n from redemptions where (redeemed_at at time zone 'Asia/Manila')::date = ${MNL}`),
      pool.query(`select count(*)::int n from redemptions where date_trunc('month', redeemed_at at time zone 'Asia/Manila') = date_trunc('month', now() at time zone 'Asia/Manila')`),
      pool.query(`select pt.id, pt.name, count(*)::int redemptions from redemptions r join partners pt on pt.id=r.partner_id
                  where r.redeemed_at > now() - interval '30 days' group by pt.id, pt.name order by redemptions desc limit 5`),
    ]);
    res.json({
      onlineNow: online.rows[0].n, dau: dau.rows[0].n, mau30d: mau.rows[0].n, activeTags: tags.rows[0].n,
      redemptionsToday: today.rows[0].n, redemptionsThisMonth: month.rows[0].n, topPartners30d: top.rows,
    });
  } catch (e) { next(e); }
});

// Read-only audit viewer (there is deliberately no write/edit/delete route for audit_logs).
reportsRouter.get('/audit-logs', async (req, res, next) => {
  try {
    const q = z.object({
      actor: z.string().uuid().optional(), action: z.string().max(60).optional(),
      from: z.string().datetime().optional(), to: z.string().datetime().optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50), offset: z.coerce.number().int().min(0).default(0),
    }).parse(req.query);
    const r = await pool.query(
      `select id, actor_id, actor_role, action_type, target_entity, target_id, old_value, new_value, ip_address, created_at
       from audit_logs
       where ($1::uuid is null or actor_id=$1) and ($2::text is null or action_type=$2)
         and ($3::timestamptz is null or created_at>=$3) and ($4::timestamptz is null or created_at<=$4)
       order by created_at desc limit $5 offset $6`,
      [q.actor ?? null, q.action ?? null, q.from ?? null, q.to ?? null, q.limit, q.offset]);
    res.json({ logs: r.rows });
  } catch (e) { next(e); }
});
