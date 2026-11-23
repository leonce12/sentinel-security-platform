"""Deployment hardening: configuration, request limits, headers, single-origin frontend,
public demo account, first-administrator bootstrap and automatic demo loading."""

import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.spa import mount_frontend
from app.core.config import Settings, get_settings
from app.core.middleware import API_CSP, SPA_CSP, BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.models import AuditLog, Role, SecurityEvent, User
from app.services import bootstrap
from tests.conftest import PASSWORD, login
from tests.helpers import record

API = "/api/v1"
KEY = "k" * 40


# ---- configuration ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw", ["postgres://u:p@h:5432/db?sslmode=require", "postgresql://u:p@h:5432/db?sslmode=require"])
def test_provider_database_urls_are_normalized(raw):
    s = Settings(secret_key=KEY, database_url=raw)
    assert s.database_url == "postgresql+psycopg://u:p@h:5432/db?sslmode=require"


def test_database_url_is_required():
    from pydantic import ValidationError
    import os
    saved = os.environ.pop("SENTINEL_DATABASE_URL")
    try:
        with pytest.raises(ValidationError):
            Settings(secret_key=KEY, _env_file=None)
    finally:
        os.environ["SENTINEL_DATABASE_URL"] = saved


def test_api_docs_off_in_production_by_default():
    assert Settings(secret_key=KEY, database_url="sqlite://", environment="production").api_docs_enabled is False
    assert Settings(secret_key=KEY, database_url="sqlite://", environment="development").api_docs_enabled is True
    assert Settings(secret_key=KEY, database_url="sqlite://", environment="production", expose_api_docs=True).api_docs_enabled


# ---- request size limit ----------------------------------------------------------------------
def _echo_app(limit: int) -> TestClient:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: __import__("fastapi").Request):
        return {"size": len(await request.body())}

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=limit)
    return TestClient(app)


def test_body_limit_by_content_length_and_by_streaming():
    client = _echo_app(100)
    assert client.post("/echo", content=b"x" * 100).json() == {"size": 100}
    assert client.post("/echo", content=b"x" * 101).status_code == 413

    def chunks():  # no Content-Length: the middleware has to count
        for _ in range(5):
            yield b"x" * 50
    response = client.post("/echo", content=chunks())
    assert response.status_code == 413 and response.json()["error"]["code"] == "payload_too_large"


def test_main_app_rejects_oversized_requests(client, headers):
    limit = get_settings().max_request_bytes
    r = client.post(f"{API}/ingest/upload", headers={**headers["admin"], "Content-Length": str(limit + 1)}, content=b"x")
    assert r.status_code == 413


# ---- headers and single-origin frontend --------------------------------------------------------
@pytest.fixture
def spa_client(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<html>sentinel-app</html>")
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path / "favicon.svg").write_text("<svg/>")
    (tmp_path.parent / "secret.txt").write_text("outside")
    app = FastAPI()

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok"}

    assert mount_frontend(app, str(tmp_path), "/api/v1")
    app.add_middleware(SecurityHeadersMiddleware)
    return TestClient(app)


def test_spa_routes_assets_and_csp(spa_client):
    page = spa_client.get("/alerts/12")
    assert page.status_code == 200 and "sentinel-app" in page.text
    assert page.headers["content-security-policy"] == SPA_CSP and "unsafe-eval" not in SPA_CSP
    assert spa_client.get("/assets/app.js").status_code == 200
    assert spa_client.get("/favicon.svg").text == "<svg/>"
    api = spa_client.get("/api/v1/health")
    assert api.headers["content-security-policy"] == API_CSP and api.headers["cache-control"] == "no-store"
    assert spa_client.get("/api/v1/unknown").status_code == 404  # API paths never fall back to the app


def test_spa_does_not_serve_files_outside_its_folder(spa_client):
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"):
        assert "outside" not in spa_client.get(path).text


def test_hsts_only_in_production(monkeypatch):
    monkeypatch.setattr(get_settings(), "environment", "production")
    app = FastAPI()

    @app.get("/x")
    def x():
        return {}
    app.add_middleware(SecurityHeadersMiddleware)
    assert "max-age=31536000" in TestClient(app).get("/x").headers["strict-transport-security"]


# ---- public demo account -----------------------------------------------------------------------
@pytest.fixture
def demo_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "public_demo", True)
    bootstrap.ensure_demo_user()
    yield get_settings().demo_username


def test_demo_login_disabled_by_default(client):
    assert client.post(f"{API}/auth/demo").status_code == 404
    assert client.get(f"{API}/auth/public-config").json()["public_demo"] is False


def test_demo_login_gives_read_only_viewer(client, demo_enabled, db):
    assert client.get(f"{API}/auth/public-config").json()["public_demo"] is True
    r = client.post(f"{API}/auth/demo")
    assert r.status_code == 200 and "sentinel_session=1" in r.headers.get("set-cookie", "")
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    me = client.get(f"{API}/auth/me", headers=h).json()
    assert me["username"] == demo_enabled and me["role"] == "viewer" and me["is_demo"] is True
    assert client.get(f"{API}/dashboard/summary", headers=h).status_code == 200
    for method, path, body in [("POST", "/events", record()), ("GET", "/audit-logs", None), ("GET", "/users", None),
                               ("POST", "/detection/run", {}), ("PATCH", "/settings", {"ai_enabled": True}),
                               ("PATCH", "/auth/me", {"full_name": "defaced"}),
                               ("POST", "/auth/change-password", {"current_password": "x", "new_password": "Another-Strong-99!"})]:
        assert client.request(method, f"{API}{path}", headers=h, json=body).status_code == 403, path
    assert db.query(AuditLog).filter_by(action="auth.demo_login").count() == 1


def test_demo_account_cannot_sign_in_with_a_password(client, demo_enabled):
    r = client.post(f"{API}/auth/login", json={"username": demo_enabled, "password": "anything-at-all-1A"})
    assert r.status_code == 401


def test_demo_account_is_forced_back_to_viewer(demo_enabled, db):
    user = db.query(User).filter_by(username=demo_enabled).one()
    user.role_id = db.query(Role).filter_by(name="admin").one().id
    user.is_active = False
    db.commit()
    bootstrap.ensure_demo_user()
    db.expire_all()
    user = db.query(User).filter_by(username=demo_enabled).one()
    assert user.role_name == "viewer" and user.is_active


# ---- bootstrap administrator -------------------------------------------------------------------
def test_bootstrap_admin_created_once(monkeypatch, db):
    s = get_settings()
    monkeypatch.setattr(s, "bootstrap_admin_username", "owner")
    monkeypatch.setattr(s, "bootstrap_admin_email", "owner@corp.example")
    monkeypatch.setattr(s, "bootstrap_admin_password", "Harbor-Strong-Pass-77")
    assert bootstrap.bootstrap_admin() == "created"
    assert bootstrap.bootstrap_admin() == "admin_exists"
    assert db.query(User).filter_by(username="owner").one().role_name == "admin"


def test_bootstrap_admin_weak_password_is_not_logged(monkeypatch, caplog):
    s = get_settings()
    monkeypatch.setattr(s, "bootstrap_admin_username", "owner")
    monkeypatch.setattr(s, "bootstrap_admin_email", "owner@corp.example")
    monkeypatch.setattr(s, "bootstrap_admin_password", "weakpw")
    with caplog.at_level(logging.ERROR):
        assert bootstrap.bootstrap_admin() == "failed"
    assert "weakpw" not in caplog.text and "Password does not meet the policy" in caplog.text


def test_bootstrap_admin_not_configured():
    assert bootstrap.bootstrap_admin() == "not_configured"


# ---- automatic demo load -----------------------------------------------------------------------
def test_demo_dataset_loads_only_into_an_empty_database(db):
    assert bootstrap.load_demo_if_empty() == "loaded"
    count = db.query(SecurityEvent).count()
    assert count > 6000
    assert bootstrap.load_demo_if_empty() == "not_needed"
    assert db.query(SecurityEvent).count() == count


# ---- session cookies and login limits ----------------------------------------------------------
def test_session_marker_set_on_login_and_cleared_on_logout(client, users):
    r = client.post(f"{API}/auth/login", json={"username": "admin", "password": PASSWORD})
    cookies = r.headers.get_list("set-cookie")
    marker = [c for c in cookies if c.startswith("sentinel_session=1")]
    assert marker and "HttpOnly" not in marker[0] and "SameSite=strict" in marker[0]
    refresh = [c for c in cookies if c.startswith("sentinel_refresh=")]
    assert "HttpOnly" in refresh[0]
    out = client.post(f"{API}/auth/logout").headers.get_list("set-cookie")
    assert any(c.startswith("sentinel_session=") and "Max-Age=0" in c for c in out)


def test_per_account_limit_ignores_client_address(client, users, monkeypatch):
    from app.api.routes import auth as auth_routes
    from app.services import users as user_service
    addresses = iter(f"198.51.100.{i}" for i in range(1, 100))
    monkeypatch.setattr(auth_routes, "client_ip", lambda request: next(addresses))
    monkeypatch.setattr(user_service, "authenticate", lambda *a, **k: (_ for _ in ()).throw(user_service.LoginFailed()))
    codes = [client.post(f"{API}/auth/login", json={"username": "viewer", "password": "guess-1A!x"}).status_code
             for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    monkeypatch.undo()
    assert login(client, "admin")  # other accounts are unaffected
