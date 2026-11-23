"""FastAPI dependencies for authentication and authorization."""

from datetime import UTC, datetime

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import ApiKey, User
from app.security.permissions import Perm, has_permission
from app.security.tokens import TokenError, decode_access_token, password_version, sha256_hex
from app.services import audit

_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (TokenError, ValueError, KeyError):
        raise unauthorized from None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    # Reject tokens issued before the most recent password change.
    if payload.get("pwd") != password_version(user.password_changed_at):
        raise unauthorized
    return user


def require(permission: Perm):
    """Dependency factory: `user = Depends(require(Perm.ALERTS_MANAGE))`."""

    def checker(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
        if not has_permission(user.role_name, permission):
            audit.record(
                db,
                "authorization.denied",
                actor=user,
                outcome="denied",
                ip_address=client_ip(request),
                details={"permission": str(permission), "path": request.url.path, "method": request.method},
                commit=True,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission for this action")
        return user

    return checker


def get_api_key(x_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> ApiKey:
    """Authenticate a machine client for the ingestion API using the X-API-Key header."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    key = db.query(ApiKey).filter(ApiKey.key_hash == sha256_hex(x_api_key)).first()
    if key is None or key.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    key.last_used_at = datetime.now(UTC)
    db.commit()
    return key
