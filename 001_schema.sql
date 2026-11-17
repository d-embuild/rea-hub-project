-- REA HUB Phase 1 MVP schema (PostgreSQL / Supabase)
create extension if not exists pgcrypto;

create type user_role      as enum ('TRAVELER','PARTNER','ADMIN');
create type tag_status     as enum ('UNCLAIMED','ACTIVE','REVOKED');
create type partner_status as enum ('PENDING','APPROVED','SUSPENDED');

-- ───────── partners ─────────
create table partners (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (length(name) between 2 and 120),
  category    text not null,
  description text,
  address     text,
  city        text,
  latitude    double precision check (latitude  between -90  and 90),
  longitude   double precision check (longitude between -180 and 180),
  photo_keys  text[] not null default '{}',          -- Cloudflare R2 object keys
  status      partner_status not null default 'PENDING',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index partners_status_category_idx on partners (status, category);
create index partners_city_idx on partners (city) where status = 'APPROVED';

-- ───────── users (profile row; credentials live in Supabase auth.users) ─────────
create table users (
  id                 uuid primary key references auth.users(id) on delete cascade,
  role               user_role not null default 'TRAVELER',
  partner_id         uuid references partners(id) on delete set null,
  display_name       text not null check (length(display_name) between 1 and 80),
  phone_enc          bytea,                 -- AES-256-GCM (iv|tag|ciphertext)
  phone_hash         text unique,           -- HMAC-SHA256 for uniqueness lookups
  phone_verified_at  timestamptz,
  consent_privacy_at timestamptz not null,  -- RA 10173 consent
  consent_terms_at   timestamptz not null,
  consent_version    text not null,
  created_at         timestamptz not null default now(),
  check (role <> 'PARTNER' or partner_id is not null)
);
create index users_partner_idx on users (partner_id) where partner_id is not null;

-- ───────── tag batches + smart tags ─────────
create table tag_batches (
  id         uuid primary key default gen_random_uuid(),
  label      text not null,
  quantity   int  not null check (quantity between 1 and 5000),
  created_by uuid not null references users(id),
  created_at timestamptz not null default now()
);

create table smart_tags (
  id           uuid primary key default gen_random_uuid(),
  batch_id     uuid not null references tag_batches(id) on delete restrict,
  serial_code  text not null unique,                    -- signature is recomputed, never stored
  status       tag_status not null default 'UNCLAIMED',
  owner_id     uuid unique references users(id) on delete set null,  -- one pass per user
  activated_at timestamptz,
  created_at   timestamptz not null default now(),
  check (status <> 'UNCLAIMED' or owner_id is null),
  check (status <> 'ACTIVE'    or owner_id is not null)
);
create index smart_tags_batch_idx  on smart_tags (batch_id);
create index smart_tags_status_idx on smart_tags (status);

-- ───────── promotions ─────────
create table promotions (
  id             uuid primary key default gen_random_uuid(),
  partner_id     uuid not null references partners(id) on delete cascade,
  title          text not null,
  description    text,
  discount_label text not null,                          -- e.g. "10% off"
  max_per_pass   int  not null default 1 check (max_per_pass > 0),   -- "1x per pass"
  max_total      int  check (max_total is null or max_total > 0),
  starts_at      timestamptz not null default now(),
  ends_at        timestamptz,
  is_active      boolean not null default true,
  created_at     timestamptz not null default now(),
  check (ends_at is null or ends_at > starts_at)
);
create index promotions_partner_idx on promotions (partner_id, is_active);

-- ───────── redemptions (append-only) ─────────
create table redemptions (
  id           uuid primary key default gen_random_uuid(),
  tag_id       uuid not null references smart_tags(id) on delete restrict,
  promotion_id uuid not null references promotions(id) on delete restrict,
  partner_id   uuid not null references partners(id)   on delete restrict,
  scanned_by   uuid not null references users(id)      on delete restrict,
  qr_nonce     text not null unique,                   -- a scanned QR can never be replayed
  redeemed_at  timestamptz not null default now()
);
create index redemptions_tag_promo_idx on redemptions (tag_id, promotion_id);
create index redemptions_promo_idx     on redemptions (promotion_id);
create index redemptions_partner_idx   on redemptions (partner_id, redeemed_at desc);

-- ───────── ratings ─────────
create table ratings (
  id         uuid primary key default gen_random_uuid(),
  partner_id uuid not null references partners(id) on delete cascade,
  user_id    uuid not null references users(id)    on delete cascade,
  stars      smallint not null check (stars between 1 and 5),
  comment    text check (length(comment) <= 500),
  created_at timestamptz not null default now(),
  unique (partner_id, user_id)
);

-- ═════════ ROW-LEVEL SECURITY ═════════
-- Clients (anon/authenticated) get READ-ONLY, scoped access. ALL writes go through
-- the Node.js API, which connects with a privileged role that bypasses RLS.
alter table users        enable row level security;
alter table partners     enable row level security;
alter table tag_batches  enable row level security;
alter table smart_tags   enable row level security;
alter table promotions   enable row level security;
alter table redemptions  enable row level security;
alter table ratings      enable row level security;

revoke all on all tables in schema public from anon, authenticated;
grant select on users, partners, smart_tags, promotions, redemptions, ratings to authenticated;
grant select on partners, promotions to anon;   -- public directory (approved only, via policy)

create policy users_select_self on users
  for select to authenticated using (id = auth.uid());

create policy partners_select_approved on partners
  for select to anon, authenticated using (status = 'APPROVED');

create policy promotions_select_live on promotions
  for select to anon, authenticated using (
    is_active and starts_at <= now() and (ends_at is null or ends_at > now())
    and exists (select 1 from partners p where p.id = partner_id and p.status = 'APPROVED'));

create policy tags_select_own on smart_tags
  for select to authenticated using (owner_id = auth.uid());

create policy redemptions_select_own on redemptions
  for select to authenticated using (
    exists (select 1 from smart_tags t where t.id = tag_id and t.owner_id = auth.uid()));

create policy ratings_select_all on ratings
  for select to authenticated using (true);

-- No INSERT/UPDATE/DELETE policies exist for client roles => all client mutations are denied.
-- tag_batches has no client policy at all => fully hidden from clients.
