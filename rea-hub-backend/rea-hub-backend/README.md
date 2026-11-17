# REA HUB Backend (Phase 1 MVP, security-hardened)

## Run locally
1. `cp .env.example .env` and fill in secrets (never commit `.env`). Set `REQUIRE_ADMIN_MFA=false` only for local dev.
2. In the Supabase SQL editor run `sql/001_schema.sql`, then `sql/002_hardening.sql`.
3. First admin: sign up in the app, then `update users set role='ADMIN' where id='<uuid>';` and enroll TOTP MFA in Supabase Auth.
4. `npm install && npm run dev` — tests: `npm test`

## Endpoints
| Method | Path | Role |
|---|---|---|
| POST | /v1/auth/profile | signed-in, phone-verified |
| DELETE | /v1/auth/account | signed-in |
| POST | /v1/tags/activate · GET /v1/tags/me | TRAVELER |
| GET | /v1/qr | TRAVELER (45s token) |
| GET | /v1/partners · /v1/partners/:id | any signed-in (browse, distance sort) |
| POST | /v1/partners/:id/ratings | TRAVELER |
| GET | /v1/redemptions/me | TRAVELER |
| GET | /v1/redemptions/partner/promotions | PARTNER |
| POST | /v1/redemptions | PARTNER (atomic) |
| POST | /v1/heartbeat | signed-in |
| POST | /v1/admin/tag-batches · PATCH /v1/admin/tags/:id/status | ADMIN + MFA |
| GET/POST/PATCH | /v1/admin/partners, /v1/admin/partners/:id, …/status | ADMIN + MFA |
| POST/PATCH | /v1/admin/promotions, /v1/admin/promotions/:id | ADMIN + MFA |
| PATCH | /v1/admin/users/:id/role | ADMIN + MFA |
| POST | /v1/admin/uploads/presign | ADMIN + MFA |
| GET | /v1/admin/analytics/summary · /v1/admin/audit-logs | ADMIN + MFA |

## Deploy
`cd docker && docker compose up -d --build` (put TLS certs in `docker/certs/`). Backups: `scripts/backup.sh`.
Load test: see header of `load/k6-rea.js`.

Full defense notes: `docs/PANEL_DEFENSE.md`
