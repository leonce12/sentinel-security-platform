from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.core.errors import NotFound
from app.database.session import get_db
from app.models import ApiKey, Role, User
from app.schemas.auth import AdminPasswordReset, ApiKeyCreate, ApiKeyCreated, ApiKeyOut, UserCreate, UserOut, UserUpdate
from app.schemas.common import Message, Page, UserRef
from app.security.deps import get_current_user, require
from app.security.permissions import ASSIGNABLE_ROLES, ROLE_DEFINITIONS, Perm, has_permission
from app.security.tokens import new_api_key
from app.services import audit, users as user_service

router = APIRouter(tags=["users"])


@router.get("/users", response_model=Page[UserOut])
def list_users(
    q: str | None = None, role: str | None = None, active: bool | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db),
):
    query = db.query(User).join(Role)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like), User.full_name.ilike(like)))
    if role:
        query = query.filter(Role.name == role)
    if active is not None:
        query = query.filter(User.is_active.is_(active))
    return paginate(query.order_by(User.username), page, page_size, UserOut.from_user)


@router.get("/users/assignable", response_model=list[UserRef])
def assignable_users(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Analysts who can receive alert or incident assignments."""
    if not (has_permission(user.role_name, Perm.ALERTS_MANAGE) or has_permission(user.role_name, Perm.INCIDENTS_MANAGE)):
        return []
    return db.query(User).join(Role).filter(Role.name.in_(ASSIGNABLE_ROLES), User.is_active.is_(True)).order_by(User.username).all()


@router.get("/roles")
def list_roles(_: User = Depends(require(Perm.USERS_MANAGE))):
    return [{"name": name, "display_name": d["display_name"], "description": d["description"],
             "permissions": sorted(str(p) for p in d["permissions"])} for name, d in ROLE_DEFINITIONS.items()]


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, actor: User = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)):
    user = user_service.create_user(db, username=body.username, email=body.email, password=body.password,
                                    full_name=body.full_name, role=body.role, is_active=body.is_active, actor=actor)
    return UserOut.from_user(user)


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, _: User = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User")
    return UserOut.from_user(user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, actor: User = Depends(require(Perm.USERS_MANAGE)),
                db: Session = Depends(get_db)):
    return UserOut.from_user(user_service.update_user(db, user_id, body.model_dump(exclude_none=True), actor))


@router.post("/users/{user_id}/reset-password", response_model=Message)
def reset_password(user_id: int, body: AdminPasswordReset, actor: User = Depends(require(Perm.USERS_MANAGE)),
                   db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User")
    user_service.validate_password(body.new_password, user.username)
    user_service.set_password(db, user, body.new_password)
    user.failed_login_count = 0
    user.locked_until = None
    audit.record(db, "user.password_reset", actor=actor, object_type="user", object_id=user.id)
    db.commit()
    return Message(message="Password reset. The user's existing sessions were revoked.")


# ---- Ingestion API keys -------------------------------------------------------------------

@router.get("/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(_: User = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)):
    return db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
def create_api_key(body: ApiKeyCreate, actor: User = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)):
    full_key, prefix, key_hash = new_api_key()
    key = ApiKey(name=body.name, prefix=prefix, key_hash=key_hash, created_by_id=actor.id)
    db.add(key)
    db.flush()
    audit.record(db, "api_key.create", actor=actor, object_type="api_key", object_id=key.id,
                 details={"name": body.name, "prefix": prefix})
    db.commit()
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(), key=full_key)


@router.post("/api-keys/{key_id}/revoke", response_model=ApiKeyOut)
def revoke_api_key(key_id: int, actor: User = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if key is None:
        raise NotFound("API key")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
        audit.record(db, "api_key.revoke", actor=actor, object_type="api_key", object_id=key.id)
        db.commit()
    return key
