import { Router } from 'express';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { env } from '../../config/env';
import { pool, withTx } from '../../db/pool';
import { encryptPII, hashPII } from '../../lib/crypto';
import { authenticate } from '../../middleware/auth';
import { audit } from '../../lib/audit';

export const authRouter = Router();
const supabaseAdmin = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

const profileSchema = z.object({
  displayName: z.string().trim().min(1).max(80),
  consentPrivacy: z.literal(true),   // RA 10173 – mandatory
  consentTerms: z.literal(true),
  consentVersion: z.string().min(1).max(20),
});

// Called once after Supabase sign-up + phone OTP. Role is ALWAYS TRAVELER here; PARTNER/ADMIN are assigned only by admins.
authRouter.post('/profile', authenticate(false), async (req, res, next) => {
  try {
    const body = profileSchema.safeParse(req.body);
    if (!body.success) return res.status(400).json({ error: 'CONSENT_REQUIRED' });
    const phone = req.user!.phone;
    if (!phone) return res.status(400).json({ error: 'PHONE_NOT_VERIFIED' }); // phone claim exists only after OTP verification
    const r = await pool.query(
      `insert into users (id, display_name, phone_enc, phone_hash, phone_verified_at,
                          consent_privacy_at, consent_terms_at, consent_version)
       values ($1,$2,$3,$4, now(), now(), now(), $5)
       on conflict (id) do nothing returning id`,
      [req.user!.id, body.data.displayName, encryptPII(phone), hashPII(phone), body.data.consentVersion],
    );
    res.status(r.rowCount ? 201 : 200).json({ ok: true });
  } catch (e: any) {
    if (e.code === '23505') return res.status(409).json({ error: 'PHONE_ALREADY_USED' });
    next(e);
  }
});

// RA 10173 right to erasure.
authRouter.delete('/account', authenticate(), async (req, res, next) => {
  try {
    const uid = req.user!.id;
    await withTx(async (c) => {
      // Revoke (not free) the pass so a deleted account's tag can't be re-claimed; redemption history stays anonymized.
      await c.query(`update smart_tags set status='REVOKED', owner_id=null where owner_id=$1`, [uid]);
      await c.query('delete from ratings where user_id=$1', [uid]);
      await audit(c, req, { action: 'ACCOUNT_ERASURE', target: 'user', targetId: uid });
    });
    const { error } = await supabaseAdmin.auth.admin.deleteUser(uid); // cascades to users row
    if (error) throw error;
    res.status(204).end();
  } catch (e) { next(e); }
});
