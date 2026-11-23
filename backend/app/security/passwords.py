"""Password hashing with Argon2id (argon2-cffi) and a basic password policy."""

import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# argon2-cffi defaults follow RFC 9106 recommendations and use the Argon2id variant.
_hasher = PasswordHasher()

# A valid hash used to equalize timing when the username does not exist.
_DUMMY_HASH = _hasher.hash("sentinel-timing-equalizer")

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Return True if the password matches. Runs a full verification even for unknown users."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_policy_errors(password: str, username: str | None = None) -> list[str]:
    """Return a list of human readable policy violations (empty list means acceptable)."""
    errors: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password) > 128:
        errors.append("Password must be at most 128 characters long.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        errors.append("Password must contain at least three of: lowercase, uppercase, digit, symbol.")
    if username and username.lower() in password.lower():
        errors.append("Password must not contain the username.")
    return errors
