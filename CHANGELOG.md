# Changelog

All notable changes to this project will be documented here.

## 2025-11-30
- Security hardening across backend:
  - Enforced Cloudflare Turnstile on register/login, added `/api/config` for public runtime config.
  - Tightened CORS and CSP; rate limiting and brute-force lockouts.
  - Switched JWT to HMAC-SHA256 with `JWT_SECRET` from environment; added verify helpers.
  - Added prepared statements and table checks to mitigate SQL injection.
- Database schema alignment:
  - Updated `schema.sql` with `users`, `passwords`, `recovery_codes` tables and indexes.
  - Lazy migration for 2FA columns and `passwords.username/tags`.
- Frontend integration:
  - Invisible Turnstile widget; dynamic sitekey via `/api/config`.
  - Sends `X-CF-Turnstile` header for auth flows.
- Deployment & config:
  - Added `[vars]` in `wrangler.toml`: `CUSTOM_DOMAIN=661985.xyz`, `TURNSTILE_SITE_KEY`.
  - Set secrets via wrangler: `TURNSTILE_SECRET`, generated `JWT_SECRET`.
  - Added `routes` to bind `661985.xyz` (requires CF zone routing).
- Bug fixes:
  - Moved `/api/config` route to top-level; fixed `generateToken` call with `env`.
  - Corrected `router.all` signature.

## 2025-11-29
- Initial worker setup and basic password routes.
- Added static asset serving via `[assets]`.
