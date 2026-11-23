"""Authentication endpoints.

Design: a short-lived JWT access token is returned in the response body and kept in
frontend memory only. A long-lived opaque refresh token is set as an HttpOnly,
SameSite=Strict cookie scoped to the /auth path, so JavaScript cannot read it and
other sites cannot send it.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.rate_limit import rate_limiter
from app.database.session import get_db
from app.models import User
from app.schemas.auth import (
    LoginRequest, MeOut, PasswordChange, ProfileUpdate, RegisterRequest, TokenResponse, UserOut,
)
from app.schemas.common import Message
from app.security.deps import client_ip, get_current_user
from app.security.permissions import ROLE_DEFINITIONS, permissions_for
from app.services import app_settings, audit, users as user_service

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "sentinel_refresh"
# Non-secret marker (value "1") readable by the frontend. It only tells the page that a
# refresh cookie may exist, so visitors without a session do not trigger a 401 on page load.
SESSION_MARKER = "sentinel_session"


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        REFRESH_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict",
        max_age=settings.refresh_token_days * 86400, path=f"{settings.api_prefix}/auth",
    )
    response.set_cookie(SESSION_MARKER, "1", httponly=False, secure=settings.cookie_secure, samesite="strict",
                        max_age=settings.refresh_token_days * 86400, path="/")


def _clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(REFRESH_COOKIE, path=f"{settings.api_prefix}/auth")
    response.delete_cookie(SESSION_MARKER, path="/")


def is_demo_account(user: User) -> bool:
    settings = get_settings()
    return settings.public_demo and user.username.lower() == settings.demo_username.lower()


def _reject_demo_changes(user: User) -> None:
    if is_demo_account(user):
        raise HTTPException(status_code=403, detail="The shared demo account is read-only")


def _rate_limit(request: Request, bucket: str, limit: int, window: int, extra: str = "") -> None:
    key = f"{bucket}:{client_ip(request)}:{extra.lower()}"
    if not rate_limiter.allow(key, limit, window):
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait and try again.",
                            headers={"Retry-After": str(window)})


def me_out(user: User) -> MeOut:
    base = UserOut.from_user(user).model_dump()
    return MeOut(**base, permissions=sorted(permissions_for(user.role_name)),
                 role_display_name=ROLE_DEFINITIONS[user.role_name]["display_name"], is_demo=is_demo_account(user))


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _rate_limit(request, "login-ip", 20, 60)
    _rate_limit(request, "login-user", 5, 60, body.username)
    # Per-account limit that ignores the client address, so rotating or spoofed
    # X-Forwarded-For values cannot multiply the attempts allowed against one account.
    if not rate_limiter.allow(f"login-account:{body.username.lower()}", 10, 60):
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait and try again.",
                            headers={"Retry-After": "60"})
    user = user_service.authenticate(db, body.username, body.password, client_ip(request))
    access, refresh = user_service.issue_tokens(db, user)
    _set_refresh_cookie(response, refresh)
    return TokenResponse(access_token=access, expires_in=get_settings().access_token_minutes * 60)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db),
            sentinel_refresh: str | None = Cookie(default=None)):
    _rate_limit(request, "refresh", 30, 60)
    if not sentinel_refresh:
        raise HTTPException(status_code=401, detail="No active session")
    _user, access, new_refresh = user_service.rotate_refresh_token(db, sentinel_refresh)
    _set_refresh_cookie(response, new_refresh)
    return TokenResponse(access_token=access, expires_in=get_settings().access_token_minutes * 60)


@router.post("/logout", response_model=Message)
def logout(request: Request, response: Response, db: Session = Depends(get_db),
           sentinel_refresh: str | None = Cookie(default=None)):
    user_service.revoke_refresh_token(db, sentinel_refresh)
    _clear_session_cookies(response)
    audit.record(db, "auth.logout", ip_address=client_ip(request), commit=True)
    return Message(message="Signed out")


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(get_current_user)):
    return me_out(user)


@router.patch("/me", response_model=MeOut)
def update_profile(body: ProfileUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _reject_demo_changes(user)
    changes = body.model_dump(exclude_none=True)
    updated = user_service.update_user(db, user.id, changes, actor=user)
    return me_out(updated)


@router.post("/change-password", response_model=Message)
def change_password(body: PasswordChange, request: Request, response: Response,
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _reject_demo_changes(user)
    _rate_limit(request, "password-change", 5, 300, user.username)
    user_service.change_password(db, user, body.current_password, body.new_password, client_ip(request))
    _clear_session_cookies(response)
    return Message(message="Password changed. Please sign in again.")


@router.get("/registration-status")
def registration_status(db: Session = Depends(get_db)):
    return {"enabled": bool(app_settings.get(db, "allow_self_registration"))}


@router.get("/public-config")
def public_config(db: Session = Depends(get_db)):
    """Non-sensitive flags the landing page needs before anyone signs in."""
    settings = get_settings()
    return {"public_demo": settings.public_demo,
            "registration_enabled": bool(app_settings.get(db, "allow_self_registration"))}


@router.post("/demo", response_model=TokenResponse)
def demo_login(request: Request, response: Response, db: Session = Depends(get_db)):
    """Sign in to the shared read-only demo account. Only available when SENTINEL_PUBLIC_DEMO is
    enabled. The account is a Viewer: it can read dashboards, events, alerts, incidents, rules
    and reports, and cannot change anything."""
    settings = get_settings()
    if not settings.public_demo:
        raise HTTPException(status_code=404, detail="Not found")
    _rate_limit(request, "demo-login", 10, 60)
    user = db.query(User).filter(User.username == settings.demo_username).first()
    if user is None or not user.is_active or user.role_name != "viewer":
        raise HTTPException(status_code=503, detail="The demo account is not available right now")
    user.last_login_at = datetime.now(UTC)
    audit.record(db, "auth.demo_login", actor=user, ip_address=client_ip(request), object_type="user",
                 object_id=user.id)
    db.commit()
    access, refresh = user_service.issue_tokens(db, user)
    _set_refresh_cookie(response, refresh)
    return TokenResponse(access_token=access, expires_in=settings.access_token_minutes * 60)


@router.post("/register", response_model=Message, status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Self-registration, only when an administrator enabled it. New accounts are inactive
    Viewers until an administrator activates them."""
    _rate_limit(request, "register", 5, 3600)
    if not app_settings.get(db, "allow_self_registration"):
        raise HTTPException(status_code=403, detail="Self-registration is disabled by the administrator")
    user_service.create_user(db, username=body.username, email=body.email, password=body.password,
                             full_name=body.full_name, role="viewer", is_active=False)
    return Message(message="Account created. An administrator must activate it before you can sign in.")
