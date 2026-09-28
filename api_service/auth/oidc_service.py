"""Native OpenID Connect helpers for SuggestArr.

The browser only receives an opaque, one-time login state. PKCE verifier,
nonce, tokens, and client credentials stay server-side.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import jwt
import requests
from api_service.auth.secret_key import load_secret_key
from itsdangerous import BadData, URLSafeTimedSerializer


class OIDCConfigurationError(RuntimeError):
    """Raised when native OIDC is enabled without its required configuration."""


class OIDCAccessDenied(RuntimeError):
    """Raised when a verified identity is not eligible for this application."""


class OIDCAuthenticationError(RuntimeError):
    """Raised when discovery, exchange, or ID-token validation fails."""


@dataclass(frozen=True)
class OIDCIdentity:
    subject: str
    username: str
    role: str
    groups: tuple[str, ...]


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    client_id: str
    client_secret: str
    public_url: str
    allowed_groups: frozenset[str]
    admin_groups: frozenset[str]
    username_claim: str

    @property
    def redirect_uri(self) -> str:
        return f"{self.public_url}/api/auth/oidc/callback"


def _groups(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple, set)):
        return tuple(str(part).strip() for part in value if str(part).strip())
    return ()


def _env_list(name: str) -> frozenset[str]:
    return frozenset(_groups(os.environ.get(name, "")))


class OIDCService:
    """Configuration, PKCE, and identity-policy helpers for OIDC login."""

    @staticmethod
    def is_enabled() -> bool:
        return os.environ.get("OIDC_ENABLED", "").strip().lower() == "true"

    @staticmethod
    def settings() -> OIDCSettings:
        issuer = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
        client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
        client_secret = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
        public_url = os.environ.get("OIDC_PUBLIC_URL", "").strip().rstrip("/")
        allowed_groups = _env_list("OIDC_ALLOWED_GROUPS")
        admin_groups = _env_list("OIDC_ADMIN_GROUPS")
        effective_allowed_groups = allowed_groups | admin_groups
        username_claim = os.environ.get("OIDC_USERNAME_CLAIM", "preferred_username").strip() or "preferred_username"

        missing = [
            name for name, value in (
                ("OIDC_ISSUER", issuer),
                ("OIDC_CLIENT_ID", client_id),
                ("OIDC_CLIENT_SECRET", client_secret),
                ("OIDC_PUBLIC_URL", public_url),
            ) if not value
        ]
        if missing:
            raise OIDCConfigurationError(f"Missing required OIDC configuration: {', '.join(missing)}")
        if not issuer.startswith("https://") or not public_url.startswith("https://"):
            raise OIDCConfigurationError("OIDC_ISSUER and OIDC_PUBLIC_URL must use HTTPS")
        if not effective_allowed_groups:
            raise OIDCConfigurationError("OIDC_ALLOWED_GROUPS or OIDC_ADMIN_GROUPS must contain at least one group")

        return OIDCSettings(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            public_url=public_url,
            allowed_groups=effective_allowed_groups,
            admin_groups=admin_groups,
            username_claim=username_claim,
        )

    @staticmethod
    def create_login_material() -> dict[str, str]:
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        return {
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_verifier": verifier,
            "code_challenge": challenge,
        }

    @staticmethod
    def authorization_url(discovery: dict[str, Any], settings: OIDCSettings, material: dict[str, str]) -> str:
        endpoint = str(discovery.get("authorization_endpoint") or "").strip()
        if not endpoint.startswith("https://"):
            raise OIDCConfigurationError("OIDC discovery document has no valid authorization_endpoint")
        query = urlencode({
            "response_type": "code",
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri,
            "scope": "openid profile email groups",
            "state": material["state"],
            "nonce": material["nonce"],
            "code_challenge": material["code_challenge"],
            "code_challenge_method": "S256",
        })
        return f"{endpoint}?{query}"

    @staticmethod
    def transaction_serializer() -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(load_secret_key(), salt="suggestarr-oidc-transaction")

    @staticmethod
    def serialize_transaction(material: dict[str, str]) -> str:
        return OIDCService.transaction_serializer().dumps({
            "state": material["state"],
            "nonce": material["nonce"],
            "code_verifier": material["code_verifier"],
        })

    @staticmethod
    def read_transaction(value: str) -> dict[str, str]:
        try:
            payload = OIDCService.transaction_serializer().loads(value, max_age=600)
        except BadData as exc:
            raise OIDCAuthenticationError("Login session is invalid or expired") from exc
        if not isinstance(payload, dict) or not all(isinstance(payload.get(key), str) for key in ("state", "nonce", "code_verifier")):
            raise OIDCAuthenticationError("Login session is invalid or expired")
        return payload

    @staticmethod
    def discover(settings: OIDCSettings) -> dict[str, Any]:
        try:
            response = requests.get(f"{settings.issuer}/.well-known/openid-configuration", timeout=10)
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise OIDCAuthenticationError("Unable to reach the configured OpenID provider") from exc
        if not isinstance(payload, dict) or payload.get("issuer") != settings.issuer:
            raise OIDCAuthenticationError("OpenID discovery issuer did not match configuration")
        return payload

    @staticmethod
    def exchange_code(discovery: dict[str, Any], settings: OIDCSettings, code: str, verifier: str) -> dict[str, Any]:
        endpoint = str(discovery.get("token_endpoint") or "").strip()
        if not endpoint.startswith("https://"):
            raise OIDCAuthenticationError("OpenID provider did not provide a valid token endpoint")
        try:
            response = requests.post(endpoint, data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.redirect_uri,
                "client_id": settings.client_id,
                "client_secret": settings.client_secret,
                "code_verifier": verifier,
            }, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise OIDCAuthenticationError("OpenID authorization-code exchange failed") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("id_token"), str):
            raise OIDCAuthenticationError("OpenID provider response did not contain an ID token")
        return payload

    @staticmethod
    def verify_id_token(discovery: dict[str, Any], settings: OIDCSettings, id_token: str, nonce: str) -> dict[str, Any]:
        jwks_uri = str(discovery.get("jwks_uri") or "").strip()
        if not jwks_uri.startswith("https://"):
            raise OIDCAuthenticationError("OpenID provider did not provide a valid JWKS URI")
        try:
            signing_key = jwt.PyJWKClient(jwks_uri, cache_keys=True).get_signing_key_from_jwt(id_token).key
            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=list(discovery.get("id_token_signing_alg_values_supported") or ["RS256"]),
                audience=settings.client_id,
                issuer=settings.issuer,
                options={"require": ["exp", "iat", "sub", "nonce"]},
            )
        except jwt.PyJWTError as exc:
            raise OIDCAuthenticationError("OpenID identity token validation failed") from exc
        if not hmac.compare_digest(str(claims.get("nonce") or ""), nonce):
            raise OIDCAuthenticationError("OpenID identity token nonce did not match")
        return claims

    @staticmethod
    def identity_from_claims(claims: dict[str, Any]) -> OIDCIdentity:
        settings = OIDCService.settings()
        subject = str(claims.get("sub") or "").strip()
        if not subject:
            raise OIDCAccessDenied("Identity token did not contain a subject")
        groups = _groups(claims.get("groups"))
        if not set(groups).intersection(settings.allowed_groups):
            raise OIDCAccessDenied("Your Pocket ID account is not permitted to access SuggestArr")
        username = str(
            claims.get(settings.username_claim)
            or claims.get("preferred_username")
            or claims.get("name")
            or claims.get("email")
            or f"oidc-{hashlib.sha256(subject.encode()).hexdigest()[:12]}"
        ).strip()
        if not username or len(username) > 64:
            username = f"oidc-{hashlib.sha256(subject.encode()).hexdigest()[:12]}"
        role = "admin" if set(groups).intersection(settings.admin_groups) else "user"
        return OIDCIdentity(subject=subject, username=username, role=role, groups=groups)
