import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { audit } from '../../lib/audit';
import { z } from 'zod';
import { pool, withTx } from '../../db/pool';
import { verifyQr } from '../../lib/crypto';
import { authenticate, requireRole } from '../../middleware/auth';

export const redemptionsRouter = Router();

class Invalid extends Error { constructor(public reason: string) { super(reason); } }

// Scanner: list this merchant's live promos to choose from.
redemptionsRouter.get('/partner/promotions', authenticate(), requireRole('PARTNER'), async (req, res, next) => {
  try {
    const r = await pool.query(
      `select id, title, discount_label, max_per_pass from promotions
       where partner_id=$1 and is_active and starts_at<=now() and (ends_at is null or ends_at>now())`,
      [req.user!.partnerId]);
    res.json({ promotions: r.rows });
  } catch (e) { next(e); }
});

// Traveler: redemption history.
redemptionsRouter.get('/me', authenticate(), requireRole('TRAVELER'), async (req, res, next) => {
  try {
    const r = await pool.query(
      `select r.id, r.redeemed_at, p.title, p.discount_label, pt.name as partner_name
       from redemptions r join smart_tags t on t.id=r.tag_id
       join promotions p on p.id=r.promotion_id join partners pt on pt.id=r.partner_id
       where t.owner_id=$1 order by r.redeemed_at desc limit 100`, [req.user!.id]);
    res.json({ redemptions: r.rows });
  } catch (e) { next(e); }
});

// Atomic redemption.
redemptionsRouter.post('/', authenticate(), requireRole('PARTNER'),
  rateLimit({ windowMs: 60_000, limit: 30, keyGenerator: (r) => r.user?.id ?? r.ip ?? 'anon' }),
  async (req, res, next) => {
  const body = z.object({ qr: z.string().max(600), promotionId: z.string().uuid() }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ status: 'INVALID', reason: 'BAD_REQUEST' });

  const qr = verifyQr(body.data.qr);                      // HMAC + 45s expiry, before touching the DB
  if (!qr.ok) return res.status(422).json({ status: 'INVALID', reason: qr.reason });

  try {
    const out = await withTx(async (c) => {
      // 1) Lock the pass row: concurrent scans of the same pass serialize here.
      const tag = await c.query('select id, status from smart_tags where id=$1 for update', [qr.payload.tid]);
      if (!tag.rowCount || tag.rows[0].status !== 'ACTIVE') throw new Invalid('PASS_NOT_ACTIVE');

      // 2) Lock the promo row (consistent order: tag -> promo) for max_total accounting.
      const pr = await c.query(
        `select p.id, p.partner_id, p.max_per_pass, p.max_total, p.is_active, p.starts_at, p.ends_at, pt.status as partner_status
         from promotions p join partners pt on pt.id=p.partner_id
         where p.id=$1 for update of p`, [body.data.promotionId]);
      const p = pr.rows[0];
      if (!p) throw new Invalid('PROMO_NOT_FOUND');
      if (p.partner_id !== req.user!.partnerId) throw new Invalid('PROMO_NOT_YOURS');
      const now = new Date();
      if (!p.is_active || p.partner_status !== 'APPROVED' || p.starts_at > now || (p.ends_at && p.ends_at <= now))
        throw new Invalid('PROMO_NOT_ACTIVE');

      // 3) Enforce redemption rules under lock.
      const perPass = await c.query('select count(*)::int n from redemptions where tag_id=$1 and promotion_id=$2', [qr.payload.tid, p.id]);
      if (perPass.rows[0].n >= p.max_per_pass) throw new Invalid('ALREADY_REDEEMED');
      if (p.max_total != null) {
        const total = await c.query('select count(*)::int n from redemptions where promotion_id=$1', [p.id]);
        if (total.rows[0].n >= p.max_total) throw new Invalid('PROMO_EXHAUSTED');
      }

      // 4) Record. qr_nonce UNIQUE also kills replay of the exact same QR.
      const ins = await c.query(
        `insert into redemptions (tag_id, promotion_id, partner_id, scanned_by, qr_nonce)
         values ($1,$2,$3,$4,$5) returning id, redeemed_at`,
        [qr.payload.tid, p.id, p.partner_id, req.user!.id, qr.payload.n]);
      await audit(c, req, { action: 'QR_REDEEM', target: 'redemption', targetId: ins.rows[0].id,
        newValue: { tagId: qr.payload.tid, promotionId: p.id, partnerId: p.partner_id } });
      return ins.rows[0];
    });
    res.json({ status: 'VALID', redemptionId: out.id, redeemedAt: out.redeemed_at });
  } catch (e: any) {
    if (e instanceof Invalid) {
      audit(pool, req, { action: 'QR_REDEEM_REJECTED', target: 'promotion', targetId: body.data.promotionId, newValue: { reason: e.reason } }).catch(() => undefined);
      return res.status(409).json({ status: 'INVALID', reason: e.reason });
    }
    if (e.code === '23505') return res.status(409).json({ status: 'INVALID', reason: 'ALREADY_REDEEMED' });
    next(e);
  }
});
