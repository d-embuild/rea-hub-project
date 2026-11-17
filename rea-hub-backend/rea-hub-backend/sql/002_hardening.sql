-- REA HUB: audit log (append-only), activity tracking, geo index
create table audit_logs (
  id            bigint generated always as identity primary key,
  actor_id      uuid,                       -- intentionally NO foreign key: survives account erasure (RA 10173 vs non-repudiation)
  actor_role    user_role,
  action_type   text not null,
  target_entity text,
  target_id     text,
  old_value     jsonb,
  new_value     jsonb,
  ip_address    text,
  created_at    timestamptz not null default now()
);
create index audit_logs_created_idx on audit_logs (created_at desc);
create index audit_logs_actor_idx   on audit_logs (actor_id, created_at desc);
create index audit_logs_action_idx  on audit_logs (action_type, created_at desc);

create function audit_logs_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_logs is append-only'; end $$;
create trigger audit_logs_no_change   before update or delete on audit_logs for each row       execute function audit_logs_immutable();
create trigger audit_logs_no_truncate before truncate          on audit_logs for each statement execute function audit_logs_immutable();

alter table audit_logs enable row level security;   -- no policies => invisible to clients
revoke all on audit_logs from anon, authenticated;

create table user_heartbeats (
  user_id      uuid primary key references users(id) on delete cascade,
  last_seen_at timestamptz not null default now()
);
create table user_activity_daily (
  user_id uuid not null references users(id) on delete cascade,
  day     date not null,
  primary key (user_id, day)
);
create index user_activity_day_idx on user_activity_daily (day);
alter table user_heartbeats     enable row level security;
alter table user_activity_daily enable row level security;
revoke all on user_heartbeats, user_activity_daily from anon, authenticated;

create index partners_geo_idx on partners (latitude, longitude) where status = 'APPROVED';
