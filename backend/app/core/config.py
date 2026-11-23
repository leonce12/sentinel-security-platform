"""Application configuration.

All configuration comes from environment variables (or a local .env file that is
never committed). Pydantic validates the values at startup so a misconfigured
deployment fails fast instead of running with unsafe defaults.
"""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    # General
    environment: str = Field(default="development", description="development | test | production")
    app_name: str = "Sentinel"
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"

    # Database. PostgreSQL is the primary, documented database. Required: there is no default,
    # so credentials can never come from code.
    database_url: str

    # Authentication. There is deliberately no default secret: the app refuses to start without one.
    secret_key: str = Field(min_length=32)
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    jwt_algorithm: str = "HS256"
    cookie_secure: bool = True
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # CORS: comma separated list of allowed frontend origins.
    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    # Upload limits
    max_upload_mb: int = 10
    max_records_per_upload: int = 50_000

    # Optional external services. All are off unless explicitly configured.
    virustotal_api_key: str | None = None
    ai_provider: str = "none"  # none | openai_compatible | anthropic
    ai_api_key: str | None = None
    ai_base_url: str | None = None
    ai_model: str | None = None
    ai_timeout_seconds: int = 30
    external_timeout_seconds: int = 10

    @field_validator("secret_key")
    @classmethod
    def reject_placeholder_secret(cls, value: str) -> str:
        if "change-me" in value or "replace" in value.lower():
            raise ValueError("SENTINEL_SECRET_KEY still contains a placeholder value")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def ai_configured(self) -> bool:
        return self.ai_provider != "none" and bool(self.ai_api_key or self.ai_base_url)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
