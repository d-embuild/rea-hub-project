import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { env } from '../../config/env';
import { pool } from '../../db/pool';
import { clean } from '../../lib/sanitize';
import { authenticate, requireRole } from '../../middleware/auth';

export const directoryRouter = Router();
directoryRouter.use(authenticate());

const photoUrls = (keys: string[]) => (env.R2_PUBLIC_BASE_URL ? keys.map((k) => `${env.R2_PUBLIC_BASE_URL}/${k}`) : []);

const listQuery = z.object({
  category: z.string().max(60).optional(),
  city: z.string().max(100).optional(),
  lat: z.coerce.number().min(-90).max(90).optional(),
  lng: z.coerce.number().min(-180).max(180).optional(),
  radiusKm: z.coerce.number().min(0.1).max(500).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

// Browse by category / location; sorted by distance when lat+lng are given.
directoryRouter.get('/', async (req, res, next) => {
  try {
    const q = listQuery.parse(req.query);
    const hasPos = q.lat !== undefined && q.lng !== undefined;
    const r = await pool.query(
      `select * from (
         select p.id, p.name, p.category, p.description, p.address, p.city, p.latitude, p.longitude, p.photo_keys,
                coalesce(rt.avg,0)::float8 as avg_rating, coalesce(rt.cnt,0)::int as rating_count,
                case when $3::float8 is null or $4::float8 is null or p.latitude is null then null else
                  6371 * acos(least(1, greatest(-1,
                    cos(radians($3::float8)) * cos(radians(p.latitude)) * cos(radians(p.longitude) - radians($4::float8))
                    + sin(radians($3::float8)) * sin(radians(p.latitude))))) end as distance_km
         from partners p
         left join (select partner_id, avg(stars) avg, count(*) cnt from ratings group by partner_id) rt on rt.partner_id = p.id
         where p.status = 'APPROVED' and ($1::text is null or p.category = $1) and ($2::text is null or p.city = $2)
       ) x
       where ($5::float8 is null or distance_km <= $5::float8)
       order by distance_km nulls last, name
       limit $6 offset $7`,
      [q.category ?? null, q.city ?? null, hasPos ? q.lat : null, hasPos ? q.lng : null, hasPos ? q.radiusKm ?? null : null, q.limit, q.offset]);
    res.json({ partners: r.rows.map(({ photo_keys, ...p }) => ({ ...p, photoUrls: photoUrls(photo_keys) })) });
  } catch (e) { next(e); }
});

directoryRouter.get('/:id', async (req, res, next) => {
  try {
    const id = z.string().uuid().parse(req.params.id);
    const p = await pool.query(
      `select p.*, coalesce(rt.avg,0)::float8 as avg_rating, coalesce(rt.cnt,0)::int as rating_count
       from partners p left join (select partner_id, avg(stars) avg, count(*) cnt from ratings group by partner_id) rt on rt.partner_id=p.id
       where p.id=$1 and p.status='APPROVED'`, [id]);
    if (!p.rowCount) return res.status(404).json({ error: 'NOT_FOUND' });
    const [promos, reviews] = await Promise.all([
      pool.query(`select id, title, description, discount_label, max_per_pass, ends_at from promotions
                  where partner_id=$1 and is_active and starts_at<=now() and (ends_at is null or ends_at>now())`, [id]),
      pool.query(`select r.stars, r.comment, r.created_at, u.display_name from ratings r join users u on u.id=r.user_id
                  where r.partner_id=$1 order by r.created_at desc limit 20`, [id]),
    ]);
    const { photo_keys, ...partner } = p.rows[0];
    res.json({ partner: { ...partner, photoUrls: photoUrls(photo_keys) }, promotions: promos.rows, reviews: reviews.rows });
  } catch (e) { next(e); }
});

directoryRouter.post('/:id/ratings', requireRole('TRAVELER'),
  rateLimit({ windowMs: 60 * 60_000, limit: 20, keyGenerator: (r) => r.user?.id ?? r.ip ?? 'anon' }),
  async (req, res, next) => {
    try {
      const id = z.string().uuid().parse(req.params.id);
      const b = z.object({ stars: z.number().int().min(1).max(5), comment: z.string().max(500).optional() }).parse(req.body);
      const r = await pool.query(
        `insert into ratings (partner_id, user_id, stars, comment)
         select $1,$2,$3,$4 where exists (select 1 from partners where id=$1 and status='APPROVED')
         on conflict (partner_id, user_id) do update set stars=excluded.stars, comment=excluded.comment, created_at=now()
         returning id`, [id, req.user!.id, b.stars, b.comment ? clean(b.comment) : null]);
      r.rowCount ? res.status(204).end() : res.status(404).json({ error: 'NOT_FOUND' });
    } catch (e) { next(e); }
  });
