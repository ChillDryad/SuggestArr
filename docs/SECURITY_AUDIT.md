# SuggestArr Security Audit Report

**Date:** 2026-09-29
**Branch:** feat/sterahi-foundation
**Scope:** Read-only audit, no files modified

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 8 |
| MEDIUM | 9 |
| LOW | 6 |
| **Total** | **26** |

---

## CRITICAL

### C-1: SSRF protection completely disabled when `allow_private=True`
**Files:** `api_service/utils/ssrf_guard.py:44,59`; all routes in `seer/routes.py`, `jellyfin/routes.py`, `plex/routes.py`

Every media-service endpoint calls `validate_url(api_url, allow_private=True)`. When `allow_private=True`:
- Line 44: The `_BLOCKED_HOSTNAMES` check is skipped
- Line 59: The entire IP-range block (loopback, private, link-local, multicast, reserved) is skipped

This means `validate_url` degrades to **scheme-only validation**. An authenticated user can supply `http://169.254.169.254/latest/meta-data/` or `http://localhost:6379/` as a media service URL, and the server will make outbound requests to those internal targets. None of these routes have `@require_role('admin')`.

**Fix:** Remove `allow_private=True` from all media-service routes. Restrict to admin-only. At minimum, always block link-local (169.254.0.0/16) and loopback (127.0.0.0/8) even when private IPs are allowed.

### C-2: Docker container runs as root with no security hardening
**Files:** `docker/Dockerfile`, `docker/docker-compose.yml`

No `USER` directive — process runs as root. No `cap_drop`, `security_opt`, `read_only`, or `user` directive in compose.

**Fix:** Add non-root user to Dockerfile. Add `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true` to compose.

### C-3: Shell command injection via `eval` in Docker entrypoint
**File:** `docker/docker_entrypoint.sh:6`

```sh
cd /app && exec uvicorn api_service.app:asgi_app $(eval echo "$args")
```

CMD arguments passed through `eval` — operator overriding CMD with shell metacharacters results in arbitrary command execution as root.

**Fix:** Remove `eval` — use `exec uvicorn api_service.app:asgi_app "$@"` directly.

---

## HIGH

### H-1: `auth_status` endpoint trusts raw `X-Forwarded-For` header for bypass authorization
**File:** `api_service/blueprints/auth/routes.py:280-289`

Reads raw `X-Forwarded-For` header (client-controlled) instead of `_peer_address()`. Attacker can send `X-Forwarded-For: 127.0.0.1` and pass `_is_trusted_local_ip` check, gaining full admin bypass in `local_bypass` mode.

**Fix:** Use `_peer_address()` from middleware.

### H-2: Refresh tokens are not rotated on use
**File:** `api_service/blueprints/auth/routes.py:449-493`

Same opaque refresh token can be used indefinitely for 7 days. Stolen tokens grant persistent access without detection.

**Fix:** Rotate refresh tokens on each use. Implement reuse detection — if a revoked token is presented, revoke all tokens for that user.

### H-3: No rate limiting on refresh endpoint allows token brute-force
**File:** `api_service/blueprints/auth/routes.py:450`

Rate limiter key function uses `g.current_user` or `g.api_key_id` — neither set for unauthenticated refresh. Falls back to `get_remote_address()` which uses spoofable `X-Forwarded-For`.

**Fix:** Lower rate limit. Add per-token-hash throttling.

### H-4: Exception messages leaked to clients in error responses
**Files:** `cleanup/routes.py:23,54,78,98`; `ai_search/routes.py:89,208,238,275,292,309`; `trakt/routes.py:250,314,317,344,419,498,542`; `config/routes.py:222,250,357`

Numerous handlers return `str(exc)` directly in JSON responses, leaking internal paths, SQL fragments, connection strings.

**Fix:** Replace all `str(exc)` in client responses with generic messages. Log full exception server-side only.

### H-5: No `require_role('admin')` on media service endpoints — any user can probe internal network
**Files:** All routes in `seer/routes.py`, `jellyfin/routes.py`, `plex/routes.py`

Combined with C-1 (SSRF), any authenticated user can supply arbitrary internal URLs and observe responses — internal network scanner.

**Fix:** Add `@require_role('admin')` to all media-service endpoints that accept user-supplied URLs.

### H-6: Docker socket access enables container escape
**File:** `api_service/blueprints/config/routes.py:475`

`/api/config/docker-info` reads from `/var/run/docker.sock`. Not admin-gated. Combined with root container (C-2), enables full container escape.

**Fix:** Add `@require_role('admin')`. Document that Docker socket should not be mounted.

### H-7: `docker-digest/<tag>` — no auth, unvalidated path component
**File:** `api_service/blueprints/config/routes.py:519-552`

`tag` parameter interpolated directly into URL without validation. Any authenticated user can make server issue requests to arbitrary Docker Hub API paths.

**Fix:** Validate `tag` against `^[a-zA-Z0-9._-]+$`. Add `@require_role('admin')`.

### H-8: JWT claims embedded in token cannot be revoked
**File:** `api_service/auth/auth_service.py:94-138`

JWT embeds `role`, `can_manage_ai`, `visible_tabs` as claims. Demoted users retain elevated access until JWT expires (15 min). No JTI revocation list.

**Fix:** Re-fetch user permissions from DB on each request, or implement JTI blocklist.

---

## MEDIUM

### M-1: Setup mode fails open on database errors
**File:** `api_service/auth/middleware.py:392-398`

DB unreachable → `_is_setup_mode()` returns `True` → ALL `/api/*` routes become public.

**Fix:** Fail closed when DB is unreachable, except on first startup.

### M-2: `auth_status` endpoint fails open with `200` on exception
**File:** `api_service/blueprints/auth/routes.py:308-316`

Returns `auth_setup_complete: False` with `200` on any exception — could expose setup wizard.

**Fix:** Return `503` on exception.

### M-3: `local_bypass` mode uses spoofable `request.remote_addr`
**File:** `api_service/auth/middleware.py:505,508,539-541`

`local_bypass` uses `request.remote_addr` (set by ProxyFix to client-controlled X-Forwarded-For), while `trusted_header` mode correctly uses `_peer_address()`.

**Fix:** Use `_peer_address()` for `local_bypass` check.

### M-4: Refresh token cookie `Secure` flag depends on `request.is_secure`
**File:** `api_service/blueprints/auth/routes.py:75`

If proxy doesn't send `X-Forwarded-Proto`, cookie won't be secure.

**Fix:** Add config option to force `Secure=True`.

### M-5: OIDC transaction cookie uses `SameSite=Lax`
**File:** `api_service/blueprints/auth/routes.py:192`

Necessary for OIDC redirect flow, but cookie is sent on top-level navigations from external sites. Mitigated by 10-minute expiry and one-time state validation.

**Fix:** Document the trade-off. Already deleted after callback processing.

### M-6: SQLite database file has no access control in Docker volume
**File:** `api_service/db/database_manager.py:15`; `docker/docker-compose.yml:9`

Database and secret key stored in volume with default permissions. Running as root, all files world-readable.

**Fix:** Set restrictive permissions. Run as non-root user (C-2).

### M-7: `SUGGESTARR_AUTH_DISABLED=true` is a documented escape hatch with no second factor
**File:** `api_service/auth/middleware.py:138`; `api_service/app.py:133-143`

Single env var completely disables auth with only a startup log warning.

**Fix:** Require confirmation token or file-based flag.

### M-8: Error handler logs full traceback — accessible via `/api/logs`
**File:** `api_service/app.py:172-175`

Full traceback with variable values logged. If logs exposed via `/api/logs` (see M-9), becomes information disclosure.

**Fix:** Sanitize traceback logging. Restrict `/api/logs` to admin.

### M-9: `/api/logs` endpoint accessible to any authenticated user
**File:** `api_service/blueprints/logs/routes.py:13`

No `@require_role('admin')` decorator. Any user can read application logs containing usernames, IPs, API key prefixes.

**Fix:** Add `@require_role('admin')`.

---

## LOW

### L-1: `update_auth_user` builds column names from dict — fragile pattern
**File:** `api_service/db/components/auth_mixin.py:410-411`

Currently safe (validated against allowlist), but f-string column names are fragile for future changes.

### L-2: `_status_counts` interpolates table name into SQL
**File:** `api_service/api/v1/blueprint.py:365`

Currently safe (hardcoded values at call sites), but function accepts any string.

### L-3: Log file path uses `os.path.join` without path traversal validation
**File:** `api_service/blueprints/logs/routes.py:40-41`

Currently not user-controlled, but fragile for future code paths.

### L-4: `requests` library version may have known vulnerabilities
**File:** `api_service/requirements.txt:20`

Verify `requests==2.34.2` against PyPI/CVE database.

### L-5: In-memory rate limiter doesn't work across multiple workers
**File:** `api_service/auth/limiter.py:8-10`

With 4 workers, effective login rate limit is 40/minute instead of 10/minute.

### L-6: `bcrypt` 5.0.0 may have compatibility concerns
**File:** `api_service/requirements.txt:5`

Verify API compatibility with bcrypt 5.x.

---

## Positive Findings (Security Strengths)

1. **Parameterized SQL everywhere** — All SQL queries use `?` or `%s` placeholders
2. **Bcrypt with cost=12** — Reasonable cost factor, constant-time verification
3. **Opaque refresh tokens** — Only SHA-256 hashes stored
4. **HttpOnly + SameSite=Strict refresh cookie** — Scoped to `/api/auth/refresh`
5. **Default-deny auth middleware** — All `/api/*` routes require JWT unless explicitly public
6. **OIDC implementation is solid** — PKCE with S256, nonce/state validation, JWKS verification
7. **Secret key management** — 32-byte CSPRNG, `0o600` permissions, env-var override
8. **Frontend path traversal protection** — `safe_join` + `realpath` + `commonpath`
9. **Error handlers in app.py** — 401/403/404/429/500 return generic messages
10. **API key design** — HMAC comparison, SHA-256 hashing, prefix identification, expiry, revocation