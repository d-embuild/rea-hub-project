import { Router } from 'express';
import { randomUUID } from 'crypto';
import { z } from 'zod';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { env } from '../../config/env';
import { pool, withTx } from '../../db/pool';
import { audit } from '../../lib/audit';
import { formatTagCode, newSerial } from '../../lib/crypto';
import { cleanStrings } from '../../lib/sanitize';
import { authenticate, requireMfa, requireRole } from '../../middleware/auth';
import { reportsRouter } from './admin.reports';

export const adminRouter = Router();
adminRouter.use(authenticate(), requireRole('ADMIN'), requireMfa);
adminRouter.use(reportsRouter);

const uuid = z.string().uuid();
const NOT_FOUND = { error: 'NOT_FOUND' };

// Whitelisted column maps: request keys -> SQL columns (never user-controlled identifiers).
const PARTNER_COLS = { name: 'name', category: 'category', description: 'description', address: 'address', city: 'city', latitude: 'latitude', longitude: 'longitude', photoKeys: 'photo_keys' };
const PROMO_COLS = { partnerId: 'partner_id', title: 'title', description: 'description', discountLabel: 'discount_label', maxPerPass: 'max_per_pass', maxTotal: 'max_total', startsAt: 'starts_at', endsAt: 'ends_at', isActive: 'is_active' };

function insertSql(table: string, cols: Record<string, string>, d: Record<string, unknown>) {
  const keys = Object.keys(cols).filter((k) => d[k] !== undefined);
  return { sql: `insert into ${table} (${keys.map((k) => cols[k]).join(', ')}) values (${keys.map((_, i) => `$${i + 1}`).join(', ')}) returning *`, vals: keys.map((k) => d[k]) };
}
function updateSql(table: string, cols: Record<string, string>, d: Record<string, unknown>, id: string) {
  const keys = Object.keys(cols).filter((k) => d[k] !== undefined);
  if (!keys.length) return null;
  return { sql: `update ${table} set ${keys.map((k, i) => `${cols[k]}=$${i + 2}`).join(', ')} where id=$1 returning *`, vals: [id, ...keys.map((k) => d[k])] };
}

// ───────── Tag batches & status ─────────
adminRouter.post('/tag-batches', async (req, res, next) => {
  try {
    const { label, quantity } = z.object({ label: z.string().min(1).max(100), quantity: z.number().int().min(1).max(5000) }).parse(req.body);
    const serials = [...new Set(Array.from({ length: quantity }, newSerial))];
    const batchId = await withTx(async (c) => {
      const b = await c.query('insert into tag_batches (label, quantity, created_by) values ($1,$2,$3) returning id', [label, serials.length, req.user!.id]);
      await c.query('insert into smart_tags (batch_id, serial_code) select $1, unnest($2::text[])', [b.rows[0].id, serials]);
      await audit(c, req, { action: 'TAG_BATCH_CREATE', target: 'tag_batch', targetId: b.rows[0].id, newValue: { label, quantity: serials.length } });
      return b.rows[0].id as string;
    });
    const csv = 'serial,activation_code\n' + serials.map((s) => `${s},${formatTagCode(s)}`).join('\n');
    res.set({ 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="rea-tags-${batchId}.csv"`, 'Cache-Control': 'no-store' }).send(csv);
  } catch (e) { next(e); }
});

adminRouter.patch('/tags/:id/status', async (req, res, next) => {
  try {
    const { status } = z.object({ status: z.enum(['ACTIVE', 'UNCLAIMED', 'REVOKED']) }).parse(req.body);
    const id = uuid.parse(req.params.id);
    const out = await withTx(async (c) => {
      const cur = (await c.query('select status, owner_id from smart_tags where id=$1 for update', [id])).rows[0];
      if (!cur) return 404;
      if ((status === 'UNCLAIMED' && cur.owner_id) || (status === 'ACTIVE' && !cur.owner_id)) return 409;
      await c.query('update smart_tags set status=$2::tag_status where id=$1', [id, status]);
      await audit(c, req, { action: 'TAG_STATUS_CHANGE', target: 'smart_tag', targetId: id, oldValue: { status: cur.status }, newValue: { status } });
      return 200;
    });
    out === 200 ? res.json({ id, status }) : res.status(out).json(out === 404 ? NOT_FOUND : { error: 'TRANSITION_NOT_ALLOWED' });
  } catch (e) { next(e); }
});

// ───────── Partners ─────────
const partnerFields = {
  name: z.string().trim().min(2).max(120), category: z.string().trim().min(2).max(60),
  description: z.string().max(2000).nullable(), address: z.string().max(300).nullable(), city: z.string().max(100).nullable(),
  latitude: z.number().min(-90).max(90).nullable(), longitude: z.number().min(-180).max(180).nullable(),
  photoKeys: z.array(z.string().regex(/^partners\/[0-9a-f-]{36}\.(jpg|png|webp)$/)).max(10),
};

adminRouter.get('/partners', async (_req, res, next) => {
  try { res.json({ partners: (await pool.query('select * from partners order by created_at desc limit 500')).rows }); } catch (e) { next(e); }
});

adminRouter.post('/partners', async (req, res, next) => {
  try {
    const d = cleanStrings(z.object(partnerFields).partial().required({ name: true, category: true }).parse(req.body));
    const q = insertSql('partners', PARTNER_COLS, d);
    const row = await withTx(async (c) => {
      const r = (await c.query(q.sql, q.vals)).rows[0];
      await audit(c, req, { action: 'PARTNER_CREATE', target: 'partner', targetId: r.id, newValue: d });
      return r;
    });
    res.status(201).json(row);
  } catch (e) { next(e); }
});

adminRouter.patch('/partners/:id', async (req, res, next) => {
  try {
    const id = uuid.parse(req.params.id);
    const d = cleanStrings(z.object(partnerFields).partial().parse(req.body));
    const q = updateSql('partners', PARTNER_COLS, d, id);
    if (!q) return res.status(400).json({ error: 'NO_FIELDS' });
    const row = await withTx(async (c) => {
      const old = (await c.query('select * from partners where id=$1 for update', [id])).rows[0];
      if (!old) return null;
      const r = (await c.query(q.sql.replace(' where id=$1', ', updated_at=now() where id=$1'), q.vals)).rows[0];
      await audit(c, req, { action: 'PARTNER_UPDATE', target: 'partner', targetId: id, oldValue: old, newValue: r });
      return r;
    });
    row ? res.json(row) : res.status(404).json(NOT_FOUND);
  } catch (e) { next(e); }
});

adminRouter.patch('/partners/:id/status', async (req, res, next) => {
  try {
    const { status } = z.object({ status: z.enum(['PENDING', 'APPROVED', 'SUSPENDED']) }).parse(req.body);
    const id = uuid.parse(req.params.id);
    const ok = await withTx(async (c) => {
      const old = (await c.query('select status from partners where id=$1 for update', [id])).rows[0];
      if (!old) return false;
      await c.query('update partners set status=$2::partner_status, updated_at=now() where id=$1', [id, status]);
      await audit(c, req, { action: 'PARTNER_STATUS_CHANGE', target: 'partner', targetId: id, oldValue: old, newValue: { status } });
      return true;
    });
    ok ? res.json({ id, status }) : res.status(404).json(NOT_FOUND);
  } catch (e) { next(e); }
});

// ───────── Promotions ─────────
const promoFields = {
  partnerId: uuid, title: z.string().trim().min(2).max(120), description: z.string().max(1000).nullable(),
  discountLabel: z.string().trim().min(1).max(60), maxPerPass: z.number().int().min(1).max(100),
  maxTotal: z.number().int().min(1).nullable(), startsAt: z.string().datetime(), endsAt: z.string().datetime().nullable(), isActive: z.boolean(),
};

adminRouter.post('/promotions', async (req, res, next) => {
  try {
    const d = cleanStrings(z.object(promoFields).partial().required({ partnerId: true, title: true, discountLabel: true }).parse(req.body));
    const q = insertSql('promotions', PROMO_COLS, d);
    const row = await withTx(async (c) => {
      const r = (await c.query(q.sql, q.vals)).rows[0];
      await audit(c, req, { action: 'PROMO_CREATE', target: 'promotion', targetId: r.id, newValue: d });
      return r;
    });
    res.status(201).json(row);
  } catch (e: any) {
    if (e.code === '23503') return res.status(400).json({ error: 'PARTNER_NOT_FOUND' });
    next(e);
  }
});

adminRouter.patch('/promotions/:id', async (req, res, next) => {
  try {
    const id = uuid.parse(req.params.id);
    const { partnerId: _ignored, ...fields } = promoFields;           // a promo can't be moved to another partner
    const d = cleanStrings(z.object(fields).partial().parse(req.body));
    const q = updateSql('promotions', PROMO_COLS, d, id);
    if (!q) return res.status(400).json({ error: 'NO_FIELDS' });
    const row = await withTx(async (c) => {
      const old = (await c.query('select * from promotions where id=$1 for update', [id])).rows[0];
      if (!old) return null;
      const r = (await c.query(q.sql, q.vals)).rows[0];
      await audit(c, req, { action: 'PROMO_UPDATE', target: 'promotion', targetId: id, oldValue: old, newValue: r });
      return r;
    });
    row ? res.json(row) : res.status(404).json(NOT_FOUND);
  } catch (e) { next(e); }
});

// ───────── Role assignment (the ONLY way to create PARTNER/ADMIN users) ─────────
adminRouter.patch('/users/:id/role', async (req, res, next) => {
  try {
    const id = uuid.parse(req.params.id);
    const b = z.object({ role: z.enum(['TRAVELER', 'PARTNER', 'ADMIN']), partnerId: uuid.optional() }).parse(req.body);
    if (id === req.user!.id) return res.status(409).json({ error: 'CANNOT_CHANGE_OWN_ROLE' });
    if (b.role === 'PARTNER' && !b.partnerId) return res.status(400).json({ error: 'PARTNER_ID_REQUIRED' });
    const out = await withTx(async (c) => {
      const old = (await c.query('select role, partner_id from users where id=$1 for update', [id])).rows[0];
      if (!old) return null;
      const next = { role: b.role, partner_id: b.role === 'PARTNER' ? b.partnerId : null };
      await c.query('update users set role=$2::user_role, partner_id=$3 where id=$1', [id, next.role, next.partner_id]);
      await audit(c, req, { action: 'USER_ROLE_CHANGE', target: 'user', targetId: id, oldValue: old, newValue: next });
      return next;
    });
    out ? res.json({ id, ...out }) : res.status(404).json(NOT_FOUND);
  } catch (e: any) {
    if (e.code === '23503') return res.status(400).json({ error: 'PARTNER_NOT_FOUND' });
    next(e);
  }
});

// ───────── Photo upload: short-lived presigned PUT to Cloudflare R2 (secrets never leave the server) ─────────
const s3 = env.R2_ACCOUNT_ID && env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY && env.R2_BUCKET
  ? new S3Client({ region: 'auto', endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`, credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY } })
  : null;
const EXT: Record<string, string> = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };

adminRouter.post('/uploads/presign', async (req, res, next) => {
  try {
    if (!s3) return res.status(503).json({ error: 'STORAGE_NOT_CONFIGURED' });
    const b = z.object({ contentType: z.enum(['image/jpeg', 'image/png', 'image/webp']), sizeBytes: z.number().int().min(1).max(5 * 1024 * 1024) }).parse(req.body);
    const key = `partners/${randomUUID()}.${EXT[b.contentType]}`;
    const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: env.R2_BUCKET!, Key: key, ContentType: b.contentType, ContentLength: b.sizeBytes }), { expiresIn: 300 });
    res.json({ key, uploadUrl, headers: { 'Content-Type': b.contentType } });
  } catch (e) { next(e); }
});
