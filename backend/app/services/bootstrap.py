"""Startup tasks for hosted deployments.

* Create the first administrator from environment variables, only if no administrator exists.
  This replaces the interactive CLI on hosts without shell access. The password is never logged.
* Ensure the shared read-only demo account exists when the public demo is enabled. It has a
  random password that nobody knows; visitors enter it through POST /auth/demo instead.
* Load the synthetic dataset in a background thread when the database has no events, so a
  fresh or recreated database becomes a working demo without manual steps.
"""

import logging
import secrets
import threading

from sqlalchemy import func

from app.core.config import get_settings
from app.database.session import SessionLocal
from app.models import Role, SecurityEvent, User
from app.security.passwords import hash_password
from app.services import audit, demo, users as user_service

logger = logging.getLogger("sentinel.bootstrap")
_demo_load_lock = threading.Lock()


def bootstrap_admin() -> str:
    settings = get_settings()
    if not (settings.bootstrap_admin_username and settings.bootstrap_admin_email and settings.bootstrap_admin_password):
        return "not_configured"
    with SessionLocal() as db:
        has_admin = db.query(User).join(Role).filter(Role.name == "admin").first() is not None
        if has_admin:
            return "admin_exists"
        try:
            user_service.create_user(db, username=settings.bootstrap_admin_username,
                                     email=settings.bootstrap_admin_email,
                                     password=settings.bootstrap_admin_password,
                                     full_name="Administrator", role="admin")
        except Exception as exc:  # report policy problems without echoing the password
            logger.error("Bootstrap administrator not created: %s %s", getattr(exc, "message", type(exc).__name__),
                         getattr(exc, "details", "") or "")
            return "failed"
    logger.info("Bootstrap administrator '%s' created", settings.bootstrap_admin_username)
    return "created"


def ensure_demo_user() -> User | None:
    settings = get_settings()
    if not settings.public_demo:
        return None
    with SessionLocal() as db:
        viewer = db.query(Role).filter_by(name="viewer").one()
        user = db.query(User).filter(func.lower(User.username) == settings.demo_username.lower()).first()
        if user is None:
            user = User(username=settings.demo_username, email=f"{settings.demo_username}@demo.invalid",
                        full_name="Demo Visitor (read-only)", role_id=viewer.id,
                        # Random, never stored or shown anywhere: the account cannot be used with a password.
                        password_hash=hash_password(secrets.token_urlsafe(48)))
            db.add(user)
            db.flush()
            audit.record(db, "user.create", actor_username="system", object_type="user", object_id=user.id,
                         details={"username": user.username, "role": "viewer", "reason": "public demo account"})
        elif user.role_id != viewer.id or not user.is_active:
            # The shared account must stay a read-only viewer whatever happened to it.
            user.role_id = viewer.id
            user.is_active = True
            audit.record(db, "user.role_change", actor_username="system", object_type="user", object_id=user.id,
                         details={"to": "viewer", "reason": "public demo account reset"})
        db.commit()
        db.refresh(user)
        return user


def load_demo_if_empty() -> str:
    if not _demo_load_lock.acquire(blocking=False):
        return "already_running"
    try:
        with SessionLocal() as db:
            if db.query(SecurityEvent.id).first() is not None:
                return "not_needed"
            logger.info("Database has no events: loading the synthetic demonstration dataset")
            result = demo.load_demo(db, actor=None)
            logger.info("Demo dataset loaded: %s", [(j["file"], j["processed"]) for j in result["jobs"]])
            return "loaded"
    except Exception:
        logger.exception("Loading the demo dataset failed")
        return "failed"
    finally:
        _demo_load_lock.release()


def run_startup_tasks() -> None:
    settings = get_settings()
    bootstrap_admin()
    ensure_demo_user()
    if settings.load_demo_on_empty:
        threading.Thread(target=load_demo_if_empty, name="demo-loader", daemon=True).start()
