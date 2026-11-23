from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.common import ORMModel

USERNAME_PATTERN = r"^[a-zA-Z0-9._-]{3,64}$"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime

    @classmethod
    def from_user(cls, user) -> "UserOut":
        return cls(
            id=user.id, username=user.username, email=user.email, full_name=user.full_name,
            role=user.role_name, is_active=user.is_active, last_login_at=user.last_login_at,
            created_at=user.created_at,
        )


class MeOut(UserOut):
    permissions: list[str]
    role_display_name: str
    is_demo: bool = False


class RegisterRequest(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    email: EmailStr
    full_name: str = Field(default="", max_length=128)
    password: str = Field(min_length=1, max_length=128)


class UserCreate(RegisterRequest):
    role: str = Field(pattern=r"^(admin|soc_analyst|it_admin|viewer)$")
    is_active: bool = True


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=128)
    email: EmailStr | None = None
    role: str | None = Field(default=None, pattern=r"^(admin|soc_analyst|it_admin|viewer)$")
    is_active: bool | None = None


class ProfileUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=128)
    email: EmailStr | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=1, max_length=128)


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=64)

    @field_validator("name")
    @classmethod
    def strip(cls, v: str) -> str:
        return v.strip()


class ApiKeyOut(ORMModel):
    id: int
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyOut):
    key: str  # shown exactly once
