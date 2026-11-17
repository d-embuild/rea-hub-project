# REA HUB — Panel Defense & Technical Decision Record

## 1. What is being delivered
Phase 1 MVP of **REA HUB**: the core loop *Traveler registers → activates a physical REA Local Pass → discovers partner establishments → redeems a promo through an anti-fraud QR scan*, plus an admin back-office. Components: Flutter app (Traveler + Partner Scanner mode), Next.js admin portal, Node.js/TypeScript API, Supabase PostgreSQL + Auth, Cloudflare R2 storage.

## 2. Why this stack (and not Java/MySQL)
| Criterion | Decision | Reason |
|---|---|---|
| Operating cost | Supabase + R2 free/low tier | Matches the client's "free vs paid services" requirement; no always-on VM to patch and pay for |
| Time to launch | Managed auth, OTP, TOTP MFA, backups | Fewer custom security components = fewer places to get security wrong |
| Security quality | Postgres Row-Level Security + parameterized queries | Database enforces access even if API code has a bug |
| Maintainability | One language (TypeScript) across API and admin web | Easier handover to the client's future developers |
The security *requirements* of the master prompt (Argon2id, OTP, MFA, audit, anti-fraud QR) are met by equivalent managed or custom controls — see §4.

## 3. What was combined
- **From the MVP prompt:** scope discipline, the core loop, free-tier stack, signed Smart Tag batches, RLS.
- **From the Master Security prompt:** immutable audit log, admin MFA, activity analytics (online/DAU/MAU), correlation-ID error handling, rate-limits per endpoint, hardened Docker/Nginx, encrypted backups, automated and load tests, mobile security requirements (§7).
- **Deliberately deferred:** premium subscriptions and payment webhooks, offline scan queue, AI recommendations, BI exports (see §8).

## 4. Security verification matrix
| Topic | Enforced by | Where | CIA / ISO 25010 |
|---|---|---|---|
| Secrets | `.env` only, validated at boot, `.gitignore`, `.env.example`, no secrets in Flutter | `config/env.ts` | Confidentiality / Security |
| Passwords & sessions | Supabase Auth (bcrypt hashing, short-lived JWT, refresh rotation with reuse detection) | Supabase | Confidentiality / Authenticity |
| Phone OTP | Supabase phone OTP; API refuses profile creation without a verified phone claim | `auth.routes.ts` | Authenticity |
| Admin MFA | TOTP (RFC 6238) via Supabase; API requires `aal2` on every admin route | `requireMfa` | Confidentiality |
| PII at rest | AES-256-GCM phone numbers; HMAC hash for uniqueness lookups | `lib/crypto.ts` | Confidentiality |
| Anti-screenshot QR | HMAC-SHA256 token, 45 s expiry, unique nonce | `signQr/verifyQr` | Integrity |
| No double redemption | Tx with `SELECT … FOR UPDATE` on pass + promo; unique nonce; limits checked under lock | `redemptions.routes.ts` | Integrity / Reliability |
| Tag forgery / guessing | Signed codes checked before DB lookup; activation rate-limited | `tags.routes.ts` | Integrity |
| Privilege escalation | Self-registration always TRAVELER; roles only via audited admin endpoint | `admin.routes.ts` | Integrity |
| Non-repudiation | Append-only `audit_logs` (DB trigger blocks UPDATE/DELETE/TRUNCATE), written inside the same transaction as the change | `002_hardening.sql`, `lib/audit.ts` | Accountability |
| Injection / IDOR | Parameterized SQL, Zod validation, UUID public IDs, RLS, whitelisted column maps | all routes | Integrity |
| XSS | Tags stripped on input; clients must output-encode reviews/descriptions | `lib/sanitize.ts` | Integrity |
| Availability | Global + per-endpoint rate limits (app and Nginx) | `app.ts`, `nginx.conf` | Availability |
| Safe errors | Generic message + `requestId`; details only in server logs | `app.ts` | Confidentiality |
| Transport & headers | TLS 1.3 at Nginx, HSTS, CSP, nosniff, X-Frame-Options DENY, no-referrer, no `X-Powered-By` | `app.ts`, `nginx.conf` | Confidentiality |

## 5. RA 10173 (Data Privacy Act)
- Explicit consent (privacy + terms + version) required and timestamped at registration.
- Right to erasure: `DELETE /v1/auth/account` removes the profile, ratings and login; the pass is revoked; the erasure is logged.
- Audit rows keep only a pseudonymous UUID (no FK, no name/phone), so accountability survives erasure.
- Phone numbers encrypted at rest; backups encrypted.

## 6. Testing evidence
- `npm test`: QR validity, expired-screenshot rejection, tamper rejection, unique nonces, tag-code signatures, PII encrypt/decrypt and tamper detection.
- `load/k6-rea.js`: 300 concurrent browsing users with p95 < 800 ms threshold, plus a 50-way simultaneous scan of one QR where **at most one** redemption may succeed.
- Not yet covered: automated DB-backed integration tests (planned with a test Supabase project).

## 7. Mobile requirements for the Flutter phase
`flutter_secure_storage` for tokens (never SharedPreferences) · `--dart-define` for public URLs only · Dio with 401-refresh interceptor · FLAG_SECURE on the QR screen (use a maintained package or native `MethodChannel`; `flutter_windowmanager` is unmaintained) · location "while using" only · `isMocked` rejection (Android only; iOS cannot detect it, so promos always require the physical QR scan) · responsive layouts (<600 dp phone, ≥600 dp tablet) · RA 10173 checkboxes and delete-account flow.

## 8. Honest limitations & roadmap
| Item | Status / reason |
|---|---|
| Offline pass & offline scan queue | Deferred. Offline scans cannot be atomically deduplicated; needs a reconciliation design (Phase 2). |
| MFA recovery codes | Supabase TOTP has none; admin recovery = a second admin or Supabase dashboard reset. |
| Certificate pinning | Deferred: breaks the app on certificate rotation unless pins are managed. |
| Payments / Premium | Phase 2 (webhook signature + idempotency design is ready to adopt from the master prompt). |
| MFA for partner cashiers | Optional in MVP to avoid slowing counters; can be enforced per partner. |

## 9. Backup & recovery
Daily encrypted `pg_dump` (AES-256, 14-day retention) via `scripts/backup.sh`, plus Supabase managed backups. Targets: **RPO ≤ 24 h, RTO ≤ 4 h** (restore dump → redeploy container → rotate secrets). Test a restore before go-live.

## 10. Likely panel questions
- **Why not Java?** Cost and handover (§2); security requirements met equivalently.
- **How is a screenshot of the QR useless?** 45 s signed expiry + single-use nonce + FLAG_SECURE.
- **What if two cashiers scan at the same instant?** Row lock serializes them; second gets `409 ALREADY_REDEEMED`.
- **What if the API is compromised?** RLS and the append-only audit trigger still protect clients' direct DB access; secrets are rotated via `.env`.
- **What if a user deletes their account?** Personal data erased; audit trail remains pseudonymous.
