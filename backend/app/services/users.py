"""User accounts, login, refresh tokens and role management."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, Conflict, NotFound
from app.models import RefreshToken, Role, User
from app.security.passwords import hash_password, needs_rehash, password_policy_errors, verify_password
from app.security.permissions import ROLE_DEFINITIONS
from app.security.tokens import create_access_token, new_opaque_token, sha256_hex
from app.services import audit


def ensure_roles(db: Session) -> None:
    for name, definition in ROLE_DEFINITIONS.items():
        if db.query(Role).filter_by(name=name).first() is None:
            db.add(Role(name=name, display_name=definition["display_name"], description=definition["description"]))
    db.commit()


def get_role(db: Session, name: str) -> Role:
    role = db.query(Role).filter_by(name=name).first()
    if role is None:
        raise AppError(f"Unknown role {name}", 422, "validation_error")
    return role


def validate_password(password: str, username: str) -> None:
    errors = password_policy_errors(password, username)
    if errors:
        raise AppError("Password does not meet the policy", 422, "weak_password", errors)


def create_user(
    db: Session, *, username: str, email: str, password: str, role: str, full_name: str = "",
    is_active: bool = True, actor: User | None = None,
) -> User:
    validate_password(password, username)
    exists = db.query(User).filter(
        or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())
    ).first()
    if exists:
        raise Conflict("A user with that username or email already exists")
    user = User(
        username=username, email=email.lower(), full_name=full_name, password_hash=hash_password(password),
        role_id=get_role(db, role).id, is_active=is_active,
    )
    db.add(user)
    db.flush()
    audit.record(db, "user.create", actor=actor, actor_username=None if actor else "system",
                 object_type="user", object_id=user.id, details={"username": username, "role": role})
    db.commit()
    db.refresh(user)
    return user


class LoginFailed(AppError):
    def __init__(self, message: str = "Invalid username or password"):
        super().__init__(message, 401, "invalid_credentials")


def authenticate(db: Session, username: str, password: str, ip: str | None) -> User:
    """Verify credentials, apply lockout, and record the attempt in the audit log."""
    settings = get_settings()
    now = datetime.now(UTC)
    user = db.query(User).filter(func.lower(User.username) == username.lower()).first()

    if user is not None and user.locked_until and user.locked_until > now:
        verify_password(password, None)  # keep timing similar
        audit.record(db, "auth.login", actor_username=username, outcome="failure", ip_address=ip,
                     object_type="user", object_id=user.id, details={"reason": "account_locked"}, commit=True)
        raise LoginFailed("Account temporarily locked after repeated failures. Try again later.")

    valid = verify_password(password, user.password_hash if user else None)
    if not valid or user is None or not user.is_active:
        reason = "unknown_user" if user is None else ("inactive" if not user.is_active and valid else "bad_password")
        if user is not None and reason == "bad_password":
            user.failed_login_count += 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_login_count = 0
                reason = "bad_password_locked"
        audit.record(db, "auth.login", actor_username=username[:64], outcome="failure", ip_address=ip,
                     object_type="user", object_id=user.id if user else None, details={"reason": reason}, commit=True)
        raise LoginFailed()

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    audit.record(db, "auth.login", actor=user, ip_address=ip, object_type="user", object_id=user.id)
    db.commit()
    return user


def issue_tokens(db: Session, user: User) -> tuple[str, str]:
    """Return (access_token, refresh_token). Only the refresh token hash is stored."""
    settings = get_settings()
    refresh = new_opaque_token()
    db.add(RefreshToken(
        user_id=user.id, token_hash=sha256_hex(refresh),
        expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_days),
    ))
    db.commit()
    return create_access_token(user.id, user.role_name, user.password_changed_at), refresh


def rotate_refresh_token(db: Session, refresh: str) -> tuple[User, str, str]:
    """Exchange a refresh token for new tokens. The old refresh token is revoked (rotation)."""
    now = datetime.now(UTC)
    record = db.query(RefreshToken).filter_by(token_hash=sha256_hex(refresh)).first()
    if record is None or record.revoked_at is not None or record.expires_at <= now:
        if record is not None and record.revoked_at is not None:
            # Reuse of a revoked token suggests theft: revoke every token of that user.
            db.query(RefreshToken).filter(RefreshToken.user_id == record.user_id,
                                          RefreshToken.revoked_at.is_(None)).update({"revoked_at": now})
            audit.record(db, "auth.refresh_reuse_detected", object_type="user", object_id=record.user_id,
                         outcome="denied", commit=True)
        raise AppError("Session expired. Please sign in again.", 401, "unauthorized")
    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        raise AppError("Session expired. Please sign in again.", 401, "unauthorized")
    record.revoked_at = now
    access, new_refresh = issue_tokens(db, user)
    return user, access, new_refresh


def revoke_refresh_token(db: Session, refresh: str | None) -> None:
    if not refresh:
        return
    record = db.query(RefreshToken).filter_by(token_hash=sha256_hex(refresh)).first()
    if record and record.revoked_at is None:
        record.revoked_at = datetime.now(UTC)
        db.commit()


def revoke_all_tokens(db: Session, user_id: int) -> None:
    db.query(RefreshToken).filter(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)).update(
        {"revoked_at": datetime.now(UTC)}
    )


def change_password(db: Session, user: User, current: str, new: str, ip: str | None) -> None:
    if not verify_password(current, user.password_hash):
        audit.record(db, "auth.password_change", actor=user, outcome="failure", ip_address=ip,
                     details={"reason": "wrong_current_password"}, commit=True)
        raise AppError("Current password is incorrect", 400, "invalid_credentials")
    if current == new:
        raise AppError("New password must differ from the current password", 422, "weak_password")
    validate_password(new, user.username)
    set_password(db, user, new)
    audit.record(db, "auth.password_change", actor=user, ip_address=ip, object_type="user", object_id=user.id)
    db.commit()


def set_password(db: Session, user: User, new: str) -> None:
    user.password_hash = hash_password(new)
    user.password_changed_at = datetime.now(UTC)  # invalidates every access token issued before now
    revoke_all_tokens(db, user.id)


def update_user(db: Session, user_id: int, changes: dict, actor: User) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User")
    if user.id == actor.id and (changes.get("is_active") is False or changes.get("role") not in (None, "admin")):
        raise AppError("You cannot deactivate or demote your own account", 400, "self_lockout")
    before = {"role": user.role_name, "is_active": user.is_active, "email": user.email, "full_name": user.full_name}
    if "email" in changes and changes["email"] is not None:
        clash = db.query(User).filter(func.lower(User.email) == changes["email"].lower(), User.id != user.id).first()
        if clash:
            raise Conflict("Email already in use")
        user.email = changes["email"].lower()
    if changes.get("full_name") is not None:
        user.full_name = changes["full_name"]
    if changes.get("role") is not None and changes["role"] != user.role_name:
        if user.role_name == "admin" and _active_admin_count(db) <= 1:
            raise AppError("At least one active administrator is required", 400, "last_admin")
        user.role_id = get_role(db, changes["role"]).id
        audit.record(db, "user.role_change", actor=actor, object_type="user", object_id=user.id,
                     details={"from": before["role"], "to": changes["role"]})
    if changes.get("is_active") is not None and changes["is_active"] != user.is_active:
        if not changes["is_active"] and user.role_name == "admin" and _active_admin_count(db) <= 1:
            raise AppError("At least one active administrator is required", 400, "last_admin")
        user.is_active = changes["is_active"]
        if not user.is_active:
            revoke_all_tokens(db, user.id)
        audit.record(db, "user.activate" if user.is_active else "user.deactivate", actor=actor,
                     object_type="user", object_id=user.id)
    audit.record(db, "user.update", actor=actor, object_type="user", object_id=user.id,
                 details={"fields": sorted(k for k, v in changes.items() if v is not None)})
    db.commit()
    db.refresh(user)
    return user


def _active_admin_count(db: Session) -> int:
    return db.query(User).join(Role).filter(Role.name == "admin", User.is_active.is_(True)).count()
