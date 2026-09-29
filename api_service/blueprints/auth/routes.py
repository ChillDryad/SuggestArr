"""
Authentication blueprint.

Public endpoints (no JWT required — listed in middleware.PUBLIC_ROUTES):
  GET  /api/auth/status   — frontend routing helper (is setup done? is auth done?)
  POST /api/auth/setup    — first-run admin creation (self-guards via user count)
  POST /api/auth/login    — credential exchange → JWT + refresh cookie
  POST /api/auth/refresh  — refresh cookie → new JWT

Protected endpoints (JWT required — enforced by middleware):
  POST /api/auth/logout   — revoke refresh token, clear cookie
  GET  /api/auth/me       — current user identity

Security decisions
------------------
- Login always calls verify_password even when the username is not found.
  This prevents timing-based username enumeration (the response time is
  dominated by the bcrypt computation regardless of whether the user exists).
- The refresh token is sent as an httpOnly cookie scoped to /api/auth/refresh.
  JavaScript cannot read it, which prevents XSS-based token theft.
- SameSite=Strict means the cookie is never sent with cross-site requests,
  providing CSRF protection for the refresh endpoint without a CSRF token.
- 401 and 403 responses contain only a generic "error" key — no stack traces,
  no token details, no internal state.
- Login errors are logged at WARNING level with the username (not the password)
  to support anomaly detection without leaking credentials to log consumers.
"""
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, make_response, g, redirect

from api_service.auth.auth_service import AuthService, MIN_PASSWORD_LENGTH, REFRESH_TOKEN_EXPIRE_DAYS
from api_service.auth.oidc_service import (
    OIDCAccessDenied,
    OIDCAuthenticationError,
    OIDCConfigurationError,
    OIDCService,
)
from api_service.auth.limiter import limiter
from api_service.auth.middleware import (
    _is_trusted_local_ip,
    _load_bypass_user_context,
    _peer_address,
    invalidate_setup_cache,
    require_interactive_auth,
)
from api_service.auth.api_key_service import ApiKeyService
from api_service.db.api_key_repository import ApiKeyRepository
from api_service.config.config import load_env_vars
from api_service.config.logger_manager import LoggerManager
from api_service.db.database_manager import DatabaseManager
from api_service.services.config_service import ConfigService
from api_service.services.tmdb.localization import display_language, normalize_language

logger = LoggerManager.get_logger("AuthRoute")

auth_bp = Blueprint('auth', __name__)

# Name of the httpOnly cookie that carries the opaque refresh token.
_REFRESH_COOKIE = "suggestarr_refresh"
_OIDC_TRANSACTION_COOKIE = "suggestarr_oidc_transaction"


def _refresh_cookie_path() -> str:
    subpath = str(load_env_vars().get('SUBPATH') or '').strip()
    return f"{subpath}/api/auth/refresh" if subpath else "/api/auth/refresh"


def _set_refresh_cookie(response, raw_refresh: str) -> None:
    response.set_cookie(
        _REFRESH_COOKIE,
        raw_refresh,
        httponly=True,
        secure=request.is_secure,
        samesite="Strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path=_refresh_cookie_path(),
    )


def _oidc_callback_path() -> str:
    subpath = str(load_env_vars().get('SUBPATH') or '').strip()
    return f"{subpath}/api/auth/oidc/callback" if subpath else "/api/auth/oidc/callback"


def _provision_oidc_user(identity):
    """Resolve a verified OIDC subject to one local account without username linking."""
    db = DatabaseManager()
    user = db.get_auth_user_by_oidc_subject(identity.subject)
    if user is None:
        username = identity.username
        # Do not claim a pre-existing local account merely because a provider
        # username collides. The fallback preserves both accounts safely.
        if db.get_auth_user_by_username(username) is not None:
            username = f"oidc-{secrets.token_hex(6)}"
        user_id = db.create_auth_user(
            username,
            AuthService.hash_password(secrets.token_urlsafe(32)),
            role=identity.role,
        )
        db.bind_oidc_subject(user_id, identity.subject)
        user = db.get_auth_user_by_id(user_id)
    if not user or not user.get("is_active", True):
        raise OIDCAccessDenied("This SuggestArr account is disabled")
    if user.get("role") != identity.role:
        db.update_auth_user_role(user["id"], identity.role)
        user = db.get_auth_user_by_id(user["id"])
    db.update_last_login(user["id"])
    return user

# Dummy bcrypt hash used for constant-time comparison when a username is not
# found.  The hash is pre-computed so it cannot be timed differently from a
# real hash lookup.  It deliberately does NOT match any password.
# IMPORTANT: this must be a structurally valid bcrypt hash (correct length,
# valid base-64 alphabet) so that bcrypt.checkpw() actually runs the full
# key-derivation work instead of raising ValueError and short-circuiting,
# which would defeat the timing-safe username-enumeration protection.
_DUMMY_HASH = "$2b$12$Mw9OodX1LL0TkdqxKIjoReHVW2LdwqWmTdAtDPXjNxT34V55xST86"


def _api_key_payload(row):
    return {key: (value.isoformat() if isinstance(value, datetime) else value) for key, value in row.items()}


@auth_bp.route('/api-keys', methods=['GET'])
@require_interactive_auth
def list_api_keys():
    user_id = int(g.current_user['id'])
    keys = ApiKeyRepository(DatabaseManager()).list_keys_for_user(user_id)
    return jsonify({'keys': [_api_key_payload(key) for key in keys], 'active_limit': 10}), 200


@auth_bp.route('/api-keys', methods=['POST'])
@require_interactive_auth
@limiter.limit('5 per hour')
def create_api_key():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    if not name or len(name) > 100:
        return jsonify({'error': 'Name must contain between 1 and 100 characters'}), 400
    expires_at = data.get('expires_at')
    if expires_at:
        try:
            expires_at = datetime.fromisoformat(str(expires_at).replace('Z', '+00:00'))
            if expires_at.tzinfo is not None:
                expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
            if expires_at <= datetime.now(timezone.utc).replace(tzinfo=None):
                raise ValueError
        except ValueError:
            return jsonify({'error': 'expires_at must be a future ISO-8601 timestamp'}), 400
    else:
        expires_at = None
    db = DatabaseManager()
    service = ApiKeyService(db)
    user_id = int(g.current_user['id'])
    if service.repository.count_active_keys_for_user(user_id) >= 10:
        return jsonify({'error': 'Active API-key limit reached'}), 409
    result = service.create_key(user_id, name, expires_at)
    logger.info('api_key.created user_id=%s key_id=%s', user_id, result['id'])
    return jsonify(_api_key_payload(result)), 201


@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@require_interactive_auth
def revoke_api_key(key_id):
    if not ApiKeyRepository(DatabaseManager()).revoke_key(int(g.current_user['id']), key_id):
        return jsonify({'error': 'Not found'}), 404
    logger.info('api_key.revoked user_id=%s key_id=%s', g.current_user['id'], key_id)
    return '', 204


# ---------------------------------------------------------------------------
# Public: native OpenID Connect authorization-code + PKCE
# ---------------------------------------------------------------------------

@auth_bp.route('/oidc/login', methods=['GET'])
@limiter.limit("10 per minute")
def oidc_login():
    if not OIDCService.is_enabled():
        return jsonify({"error": "OpenID Connect is not enabled"}), 404
    try:
        settings = OIDCService.settings()
        discovery = OIDCService.discover(settings)
        material = OIDCService.create_login_material()
        response = make_response(redirect(OIDCService.authorization_url(discovery, settings, material)))
        response.set_cookie(
            _OIDC_TRANSACTION_COOKIE,
            OIDCService.serialize_transaction(material),
            httponly=True,
            secure=request.is_secure,
            samesite="Lax",
            max_age=600,
            path=_oidc_callback_path(),
        )
        return response
    except (OIDCConfigurationError, OIDCAuthenticationError) as exc:
        logger.warning("OIDC login could not start: %s", exc)
        return jsonify({"error": "OpenID Connect is unavailable"}), 503


@auth_bp.route('/oidc/callback', methods=['GET'])
@limiter.limit("20 per minute")
def oidc_callback():
    if not OIDCService.is_enabled():
        return jsonify({"error": "OpenID Connect is not enabled"}), 404
    try:
        settings = OIDCService.settings()
        transaction = OIDCService.read_transaction(request.cookies.get(_OIDC_TRANSACTION_COOKIE, ""))
        state = request.args.get("state", "")
        code = request.args.get("code", "")
        if not code or not state or not secrets.compare_digest(state, transaction["state"]):
            raise OIDCAuthenticationError("Login state did not match")
        discovery = OIDCService.discover(settings)
        tokens = OIDCService.exchange_code(discovery, settings, code, transaction["code_verifier"])
        claims = OIDCService.verify_id_token(discovery, settings, tokens["id_token"], transaction["nonce"])
        user = _provision_oidc_user(OIDCService.identity_from_claims(claims))
        raw_refresh, hashed_refresh = AuthService.generate_refresh_token()
        DatabaseManager().store_refresh_token(
            user["id"], hashed_refresh,
            datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
        response = make_response(redirect(f"{settings.public_url}/dashboard"))
        _set_refresh_cookie(response, raw_refresh)
    except OIDCAccessDenied as exc:
        logger.warning("OIDC authorization denied: %s", exc)
        response = make_response(redirect(f"{os.environ.get('OIDC_PUBLIC_URL', '').rstrip('/')}/login?oidc_error=denied"))
    except (OIDCConfigurationError, OIDCAuthenticationError) as exc:
        logger.warning("OIDC callback failed: %s", exc)
        response = make_response(redirect(f"{os.environ.get('OIDC_PUBLIC_URL', '').rstrip('/')}/login?oidc_error=failed"))
    response.delete_cookie(_OIDC_TRANSACTION_COOKIE, path=_oidc_callback_path())
    return response


# ---------------------------------------------------------------------------
# Public: setup-state probe
# ---------------------------------------------------------------------------

@auth_bp.route('/status', methods=['GET'])
@limiter.exempt
def auth_status():
    """
    Return the current setup state so the SPA can decide which screen to show.

    This endpoint is intentionally public (no JWT required) because the
    frontend needs it before any authentication takes place.

    Response JSON:
      auth_setup_complete  — True once the first admin account has been created.
      app_setup_complete   — True once SETUP_COMPLETED is set in config.yaml.
    """
    try:
        db = DatabaseManager()
        auth_done = db.get_auth_user_count() > 0

        config = ConfigService.get_runtime_config()
        app_done = bool(config.get('SETUP_COMPLETED', False))
        allow_registration = bool(config.get('ALLOW_REGISTRATION', False))

        auth_mode = (os.environ.get("AUTH_MODE") or "").strip().lower()
        if not auth_mode:
            auth_mode = str(load_env_vars().get("AUTH_MODE", "enabled")).strip().lower()
        if os.environ.get("SUGGESTARR_AUTH_DISABLED", "").lower() == "true":
            auth_mode = "disabled"

        current_user = getattr(g, "current_user", None)
        bypass = False

        # Trusted-header identities are "signed in without a token", exactly
        # like the bypass modes below — the proxy did the authenticating.  The
        # SPA gates on `authenticated && bypass` (router/index.js:
        # isBypassAuthenticated), so reporting only `authenticated` leaves it
        # showing a login form to a user the proxy already let in.
        if current_user and getattr(g, "auth_method", "") == "trusted_header":
            bypass = True

        # /api/auth/status is public, so middleware returns before injecting
        # bypass context. Recreate equivalent bypass checks here.
        if not current_user:
            client_ip = _peer_address()
            if auth_mode == "disabled":
                current_user = _load_bypass_user_context()
                bypass = True
            elif auth_mode == "local_bypass" and _is_trusted_local_ip(client_ip):
                current_user = _load_bypass_user_context()
                bypass = True

        authenticated = bool(current_user)

        response = {
            "auth_setup_complete": auth_done,
            "app_setup_complete": app_done,
            "allow_registration": allow_registration,
            "oidc_enabled": OIDCService.is_enabled(),
            "authenticated": authenticated,
        }

        if authenticated:
            response["username"] = current_user.get("username", "")
            if bypass:
                response["bypass"] = True

        return jsonify(response), 200
    except Exception as exc:
        logger.error("Error reading auth status: %s", exc)
        return jsonify({
            "auth_setup_complete": False,
            "app_setup_complete": False,
            "allow_registration": False,
            "authenticated": False,
            "error": "Service temporarily unavailable",
        }), 503


# ---------------------------------------------------------------------------
# Public: first-run admin creation
# ---------------------------------------------------------------------------

@auth_bp.route('/setup', methods=['POST'])
@limiter.limit("5 per hour")
def setup():
    """
    Create the very first admin account.

    Self-guarded: returns 403 if any auth user already exists so this
    endpoint cannot be used to escalate privileges after initial setup.

    Rate-limited to 5 attempts per hour per IP.

    Request JSON:
      username  (str) — desired login name
      password  (str) — must be >= MIN_PASSWORD_LENGTH characters

    Response (201): { "message": "Admin account created" }
    Response (400): { "error": "<validation message>" }
    Response (403): { "error": "Setup already completed" }
    """
    db = DatabaseManager()
    if db.get_auth_user_count() > 0:
        # After setup, this endpoint becomes a no-op regardless of credentials.
        return jsonify({"error": "Setup already completed"}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(username) > 64:
        return jsonify({"error": "Username must be 64 characters or fewer"}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({"error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters"}), 400

    password_hash = AuthService.hash_password(password)
    db.create_auth_user(username, password_hash, role="admin")

    # Immediately invalidate the setup-mode cache so the middleware starts
    # enforcing authentication on the very next request.
    invalidate_setup_cache()

    logger.info("Initial admin account created: %r", username)
    return jsonify({"message": "Admin account created"}), 201


# ---------------------------------------------------------------------------
# Public: credential exchange
# ---------------------------------------------------------------------------

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """
    Authenticate with username and password.

    On success:
      - Returns a short-lived JWT access token in the JSON body.
      - Sets an httpOnly refresh token cookie scoped to /api/auth/refresh.

    Rate-limited to 10 attempts per minute per IP to mitigate brute-force.

    Request JSON:
      username  (str)
      password  (str)

    Response (200):
      { "access_token": "<jwt>", "role": "<role>", "username": "<username>" }
    Response (400): { "error": "Username and password are required" }
    Response (401): { "error": "Invalid credentials" }
    Response (403): { "error": "Account is disabled" }
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    db = DatabaseManager()
    user = db.get_auth_user_by_username(username)

    # Always run bcrypt even if the user does not exist so that the response
    # time is constant regardless of username validity (timing-safe).
    stored_hash = user["password_hash"] if user else _DUMMY_HASH
    password_ok = AuthService.verify_password(password, stored_hash)

    if not password_ok or user is None:
        logger.warning("Failed login attempt for username: %r from %s", username, request.remote_addr)
        return jsonify({"error": "Invalid credentials"}), 401

    if not user.get("is_active", True):
        logger.warning("Login attempt for disabled account: %r", username)
        return jsonify({"error": "Account is disabled"}), 403

    # Issue tokens
    access_token = AuthService.create_access_token(user["id"], user["username"], user["role"])
    raw_refresh, hashed_refresh = AuthService.generate_refresh_token()
    expires_at = datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    db.store_refresh_token(user["id"], hashed_refresh, expires_at)
    db.update_last_login(user["id"])

    logger.info("Successful login: %r from %s", username, request.remote_addr)

    response = make_response(
        jsonify({
            "access_token": access_token,
            "role": user["role"],
            "username": user["username"],
        }),
        200,
    )

    # httpOnly — JavaScript cannot read this cookie (XSS protection).
    # SameSite=Strict — cookie is not sent on cross-site requests (CSRF protection).
    # Its path is restricted to the refresh endpoint to limit exposure.
    _set_refresh_cookie(response, raw_refresh)

    return response


# ---------------------------------------------------------------------------
# Public: access-token renewal
# ---------------------------------------------------------------------------

@auth_bp.route('/refresh', methods=['POST'])
@limiter.limit("30 per minute")
def refresh():
    """
    Issue a new short-lived JWT access token using the httpOnly refresh cookie.

    The refresh cookie is sent automatically by the browser because the
    request path matches the cookie's path attribute.

    Token rotation: on each successful refresh, the old refresh token is
    revoked and a new one is issued.  If a revoked token is presented again
    (reuse detection), all tokens for that user are burned to force
    re-authentication.

    Response (200): { "access_token": "<jwt>" }
    Response (401): { "error": "<reason>" }
    """
    raw_refresh = request.cookies.get(_REFRESH_COOKIE)
    if not raw_refresh:
        return jsonify({"error": "Refresh token missing"}), 401

    token_hash = AuthService.hash_refresh_token(raw_refresh)
    db = DatabaseManager()
    record = db.get_refresh_token(token_hash)

    if not record:
        # Token not found among non-revoked tokens. Check if it was revoked
        # — if so, this is a reused/stolen token: burn the whole family.
        revoked_record = db.get_refresh_token_any(token_hash)
        if revoked_record and revoked_record.get("revoked"):
            logger.warning(
                "Refresh token reuse detected for user_id=%s — revoking all tokens",
                revoked_record["user_id"],
            )
            db.revoke_all_user_refresh_tokens(revoked_record["user_id"])
        return jsonify({"error": "Invalid refresh token"}), 401

    # Check expiry in Python (DB stores as ISO string, not a DB-native check).
    expires_raw = record["expires_at"]
    if isinstance(expires_raw, str):
        expires_at = datetime.fromisoformat(expires_raw)
    else:
        expires_at = expires_raw

    # Ensure timezone-aware comparison.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(tz=timezone.utc):
        db.revoke_refresh_token(token_hash)
        return jsonify({"error": "Refresh token expired"}), 401

    user = db.get_auth_user_by_id(record["user_id"])
    if not user or not user.get("is_active", True):
        return jsonify({"error": "User not found or disabled"}), 401

    # Rotate: revoke the old refresh token and issue a new one.
    db.revoke_refresh_token(token_hash)
    new_raw_refresh, new_token_hash = AuthService.generate_refresh_token()
    new_expires = datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    db.store_refresh_token(user["id"], new_token_hash, new_expires)

    access_token = AuthService.create_access_token(user["id"], user["username"], user["role"])
    response = jsonify({"access_token": access_token})
    _set_refresh_cookie(response, new_raw_refresh)
    return response, 200


# ---------------------------------------------------------------------------
# Protected: logout
# ---------------------------------------------------------------------------

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Revoke the current refresh token and clear the cookie.

    The JWT access token naturally expires after ACCESS_TOKEN_EXPIRE_MINUTES
    (15 min) — no server-side access-token blocklist is maintained.

    This endpoint does NOT require the JWT middleware to pass (the middleware
    runs first and will enforce auth for non-public routes), but it is
    intentionally safe even if called without a valid JWT because the only
    state change is revoking a cookie-bound refresh token.

    Response (200): { "message": "Logged out" }
    """
    raw_refresh = request.cookies.get(_REFRESH_COOKIE)
    if raw_refresh:
        token_hash = AuthService.hash_refresh_token(raw_refresh)
        DatabaseManager().revoke_refresh_token(token_hash)

    response = make_response(jsonify({"message": "Logged out"}), 200)
    # Clear the cookie by expiring it immediately.
    subpath = str(load_env_vars().get('SUBPATH') or '').strip()
    refresh_path = f"{subpath}/api/auth/refresh" if subpath else "/api/auth/refresh"
    response.delete_cookie(_REFRESH_COOKIE, path=refresh_path)
    return response


# ---------------------------------------------------------------------------
# Protected: current-user identity
# ---------------------------------------------------------------------------

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """
    Self-registration endpoint for new user accounts.

    Gated by the ALLOW_REGISTRATION config flag.  When disabled (the default),
    this endpoint always returns 403 so that only admins can create accounts.
    When enabled, anyone can create a user-level account with role='user'.

    Rate-limited to 5 attempts per hour per IP to limit abuse.

    Request JSON:
      username  (str) — desired login name
      password  (str) — must be >= MIN_PASSWORD_LENGTH characters

    Response (201): { "message": "Account created" }
    Response (400): { "error": "<validation message>" }
    Response (403): { "error": "Registration is disabled" }
    Response (409): { "error": "Username already taken" }
    """
    config = ConfigService.get_runtime_config()
    if not config.get('ALLOW_REGISTRATION', False):
        return jsonify({"error": "Registration is disabled"}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(username) > 64:
        return jsonify({"error": "Username must be 64 characters or fewer"}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({"error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters"}), 400

    password_hash = AuthService.hash_password(password)
    try:
        DatabaseManager().create_auth_user(username, password_hash, role="user")
    except Exception:
        return jsonify({"error": "Username already taken"}), 409

    logger.info("Self-registration: new account created: %r", username)
    return jsonify({"message": "Account created"}), 201


# ---------------------------------------------------------------------------
# Protected: current-user identity
# ---------------------------------------------------------------------------

@auth_bp.route('/me', methods=['GET'])
def me():
    """
    Return the authenticated user's identity.

    Requires a valid JWT (enforced by the middleware — g.current_user is
    guaranteed to be set by the time this handler runs).

    Response (200):
      { "id": "<user_id>", "username": "<name>", "role": "<role>",
        "language": "<code or null>", "display_language": "<code>" }

    `language` is the person's own choice (null = the default);
    `display_language` is what titles are actually shown in.
    """
    body = dict(g.current_user)
    try:
        own = DatabaseManager().get_user_language(int(g.current_user["id"]))
    except Exception:
        own = None
    body["language"] = own
    body["display_language"] = display_language(own, load_env_vars())
    return jsonify(body), 200


# ---------------------------------------------------------------------------
# Protected: update own profile
# ---------------------------------------------------------------------------

@auth_bp.route('/me', methods=['PATCH'])
def update_me():
    """
    Update the authenticated user's own username and/or password.

    Username change:
      - The new username must be unique and ≤ 64 characters.
      - A fresh JWT with the updated username is returned in the response so
        the client can replace its in-memory token without a separate refresh.

    Password change:
      - current_password must be provided and correct.
      - new_password must be >= MIN_PASSWORD_LENGTH characters.

    Request JSON (all fields optional, at least one required):
      language          (str|null) — display language for titles, e.g. "de";
                                     null or "" returns to the default
      username          (str) — desired new login name
      current_password  (str) — required when new_password is provided
      new_password      (str) — must be >= MIN_PASSWORD_LENGTH characters

    Response (200):
      { "message": "Profile updated" }
      OR (if username changed):
      { "message": "Profile updated", "access_token": "<new_jwt>" }
    Response (400): { "error": "<validation message>" }
    Response (401): { "error": "Current password is incorrect" }
    Response (409): { "error": "Username already taken" }
    """
    user_id = int(g.current_user["id"])
    data = request.get_json(silent=True) or {}
    db = DatabaseManager()

    # Everything is validated first and written together at the end, so a
    # request that fails (a wrong password, say) changes nothing.
    updates = {}

    # --- Display language ---
    # Needs no password: a language change on its own is a valid update.
    if "language" in data:
        requested_language = data.get("language")
        if requested_language in (None, ""):
            updates["language"] = None
        else:
            updates["language"] = normalize_language(requested_language)
            if updates["language"] is None:
                return jsonify({"error": "language must look like 'de' or 'pt-BR'"}), 400

    new_username = (data.get("username") or "").strip()
    if new_username:
        if len(new_username) > 64:
            return jsonify({"error": "Username must be 64 characters or fewer"}), 400
        updates["username"] = new_username

    # --- Password change ---
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    if new_password:
        if not current_password:
            return jsonify({"error": "Current password is required"}), 400
        if len(new_password) < MIN_PASSWORD_LENGTH:
            return jsonify({"error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters"}), 400
        user = db.get_auth_user_by_id(user_id)
        if not user or not AuthService.verify_password(current_password, user["password_hash"]):
            return jsonify({"error": "Current password is incorrect"}), 401
        updates["password_hash"] = AuthService.hash_password(new_password)

    if not updates:
        return jsonify({"error": "No changes provided"}), 400

    try:
        db.update_auth_user_profile(user_id, updates)
    except Exception:
        # Unique constraint violation on username.
        return jsonify({"error": "Username already taken"}), 409

    resp_body = {"message": "Profile updated"}

    # Re-issue access token if username changed so the JWT stays accurate.
    if "username" in updates:
        updated_user = db.get_auth_user_by_id(user_id)
        new_token = AuthService.create_access_token(
            updated_user["id"], updated_user["username"], updated_user["role"]
        )
        resp_body["access_token"] = new_token

    logger.info("User id=%d updated their profile: fields=%s", user_id, list(updates.keys()))
    return jsonify(resp_body), 200
