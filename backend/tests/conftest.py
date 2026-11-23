"""Test configuration.

Tests run against a real PostgreSQL database (SENTINEL_TEST_DATABASE_URL), the same engine
used in production, so constraints, JSONB and the audit trigger are exercised. The schema
is created with Alembic migrations, which also tests the migrations themselves.
"""

import os
import secrets

os.environ.setdefault(
    "SENTINEL_DATABASE_URL",
    os.environ.get("SENTINEL_TEST_DATABASE_URL", "postgresql+psycopg://sentinel:sentinel_dev@localhost:5432/sentinel_test"),
)
os.environ["SENTINEL_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["SENTINEL_COOKIE_SECURE"] = "false"
os.environ["SENTINEL_ENVIRONMENT"] = "test"
os.environ["SENTINEL_AI_PROVIDER"] = "none"
os.environ.pop("SENTINEL_VIRUSTOTAL_API_KEY", None)

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.rate_limit import rate_limiter  # noqa: E402
from app.database.session import SessionLocal, engine  # noqa: E402
from app.services import demo, users as user_service  # noqa: E402

BACKEND = Path(__file__).resolve().parents[1]
PASSWORD = "Correct-Horse-42!"
ROLES = ("admin", "soc_analyst", "it_admin", "viewer")


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    command.upgrade(cfg, "head")
    yield


@pytest.fixture(autouse=True)
def clean_tables():
    with engine.begin() as conn:
        tables = [r[0] for r in conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version'"))]
        conn.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE"))
    rate_limiter.reset()
    with SessionLocal() as db:
        demo.seed_reference_data(db)
    from app.ai import service as ai_service
    from app.intelligence import service as intel_service
    ai_service.set_provider_override(None)
    intel_service.set_provider_override(None)
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    from app.main import app
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def users(db):
    created = {}
    for role in ROLES:
        username = role.replace("_", "")
        created[role] = user_service.create_user(db, username=username, email=f"{username}@corp.example",
                                                 password=PASSWORD, role=role, full_name=role.title())
    return created


def login(client, username: str, password: str = PASSWORD) -> dict:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def headers(client, users):
    """Authorization headers for every role."""
    return {role: login(client, user.username) for role, user in users.items()}
