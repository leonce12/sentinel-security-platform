"""JWT access tokens, opaque refresh tokens and API keys."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import get_settings


class TokenError(Exception):
    pass


def create_access_token(user_id: int, role: str, password_changed_at: datetime) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        # Tokens issued before a password change are rejected (see deps.get_current_user).
        "pwd": password_version(password_changed_at),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def password_version(changed_at: datetime) -> int:
    """Microsecond timestamp of the last password change, embedded in access tokens."""
    return int(changed_at.timestamp() * 1_000_000)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],  # never accept "none" or unexpected algorithms
            options={"require": ["exp", "sub", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid or expired token") from exc
    if payload.get("type") != "access":
        raise TokenError("Wrong token type")
    return payload


def new_opaque_token() -> str:
    """Random token for refresh tokens. Only its SHA-256 is stored in the database."""
    return secrets.token_urlsafe(48)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, sha256). The full key is shown to the admin once."""
    prefix = "snt_" + secrets.token_hex(4)
    full_key = f"{prefix}.{secrets.token_urlsafe(32)}"
    return full_key, prefix, sha256_hex(full_key)
