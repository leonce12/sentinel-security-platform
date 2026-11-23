from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import get_settings
from app.models import AuditLog, User
from tests.conftest import PASSWORD, login

API = "/api/v1"


def test_login_success_returns_token_and_httponly_refresh_cookie(client, users):
    r = client.post(f"{API}/auth/login", json={"username": "admin", "password": PASSWORD})
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"
    cookie = r.headers["set-cookie"]
    assert "sentinel_refresh=" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert "Path=/api/v1/auth" in cookie


def test_login_is_case_insensitive_on_username(client, users):
    assert client.post(f"{API}/auth/login", json={"username": "ADMIN", "password": PASSWORD}).status_code == 200


def test_wrong_password_and_unknown_user_give_same_error(client, users, db):
    bad = client.post(f"{API}/auth/login", json={"username": "admin", "password": "nope-nope-nope"})
    unknown = client.post(f"{API}/auth/login", json={"username": "ghost", "password": "nope-nope-nope"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json()["error"]["message"] == unknown.json()["error"]["message"]
    failures = db.query(AuditLog).filter_by(action="auth.login", outcome="failure").all()
    assert {f.details["reason"] for f in failures} == {"bad_password", "unknown_user"}


def test_account_locks_after_repeated_failures(client, users, db, monkeypatch):
    # Disable the per-minute rate limit so the lockout logic itself is tested.
    from app.core import rate_limit
    monkeypatch.setattr(rate_limit.rate_limiter, "allow", lambda *a, **k: True)
    for _ in range(get_settings().max_failed_logins):
        client.post(f"{API}/auth/login", json={"username": "viewer", "password": "wrong-password-1"})
    r = client.post(f"{API}/auth/login", json={"username": "viewer", "password": PASSWORD})
    assert r.status_code == 401
    assert "locked" in r.json()["error"]["message"].lower()
    db.expire_all()
    assert db.query(User).filter_by(username="viewer").one().locked_until > datetime.now(UTC)


def test_login_rate_limited_per_user(client, users):
    codes = [client.post(f"{API}/auth/login", json={"username": "it_admin", "password": "x"}).status_code
             for _ in range(7)]
    assert 429 in codes


def test_inactive_user_cannot_log_in(client, users, db):
    user = db.query(User).filter_by(username="viewer").one()
    user.is_active = False
    db.commit()
    assert client.post(f"{API}/auth/login", json={"username": "viewer", "password": PASSWORD}).status_code == 401


def test_me_never_exposes_password_hash(client, headers):
    body = client.get(f"{API}/auth/me", headers=headers["admin"]).json()
    assert "password_hash" not in str(body) and "argon2" not in str(body)
    assert body["role"] == "admin" and "users:manage" in body["permissions"]


def test_passwords_are_stored_with_argon2id(users):
    assert users["admin"].password_hash.startswith("$argon2id$")


def test_requests_without_or_with_bad_tokens_are_rejected(client, users):
    assert client.get(f"{API}/auth/me").status_code == 401
    assert client.get(f"{API}/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    # Token signed with a different key
    forged = jwt.encode({"sub": "1", "type": "access", "exp": datetime.now(UTC) + timedelta(minutes=5)}, "x" * 40,
                        algorithm="HS256")
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    # Unsigned "none" algorithm token
    none_token = jwt.encode({"sub": "1", "type": "access", "exp": datetime.now(UTC) + timedelta(minutes=5)}, None,
                            algorithm="none")
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {none_token}"}).status_code == 401


def test_expired_token_rejected(client, users):
    s = get_settings()
    user = users["admin"]
    expired = jwt.encode({"sub": str(user.id), "type": "access", "role": "admin",
                          "pwd": int(user.password_changed_at.timestamp() * 1_000_000),
                          "exp": datetime.now(UTC) - timedelta(seconds=5)}, s.secret_key, algorithm="HS256")
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_refresh_rotates_and_detects_reuse(client, users):
    client.post(f"{API}/auth/login", json={"username": "admin", "password": PASSWORD})
    first_cookie = client.cookies.get("sentinel_refresh")
    r = client.post(f"{API}/auth/refresh")
    assert r.status_code == 200
    second_cookie = client.cookies.get("sentinel_refresh")
    assert second_cookie != first_cookie
    # Replaying the old (revoked) token fails and revokes the whole session family.
    client.cookies.set("sentinel_refresh", first_cookie, path="/api/v1/auth")
    assert client.post(f"{API}/auth/refresh").status_code == 401
    client.cookies.set("sentinel_refresh", second_cookie, path="/api/v1/auth")
    assert client.post(f"{API}/auth/refresh").status_code == 401


def test_logout_revokes_refresh_token(client, users):
    client.post(f"{API}/auth/login", json={"username": "admin", "password": PASSWORD})
    token = client.cookies.get("sentinel_refresh")
    client.post(f"{API}/auth/logout")
    client.cookies.set("sentinel_refresh", token, path="/api/v1/auth")
    assert client.post(f"{API}/auth/refresh").status_code == 401


def test_change_password_policy_and_token_invalidation(client, users):
    h = login(client, "socanalyst")
    weak = client.post(f"{API}/auth/change-password", headers=h,
                       json={"current_password": PASSWORD, "new_password": "short"})
    assert weak.status_code == 422 and weak.json()["error"]["code"] == "weak_password"
    wrong = client.post(f"{API}/auth/change-password", headers=h,
                        json={"current_password": "wrong-one-123", "new_password": "Another-Strong-99!"})
    assert wrong.status_code == 400
    ok = client.post(f"{API}/auth/change-password", headers=h,
                     json={"current_password": PASSWORD, "new_password": "Another-Strong-99!"})
    assert ok.status_code == 200
    assert client.get(f"{API}/auth/me", headers=h).status_code == 401  # old access token no longer valid
    assert login(client, "socanalyst", "Another-Strong-99!")


def test_self_registration_disabled_by_default(client, users):
    r = client.post(f"{API}/auth/register", json={"username": "newbie", "email": "newbie@corp.example",
                                                  "password": "A-Valid-Password-1"})
    assert r.status_code == 403


def test_self_registration_creates_inactive_viewer_when_enabled(client, headers, db):
    client.patch(f"{API}/settings", headers=headers["admin"], json={"allow_self_registration": True})
    r = client.post(f"{API}/auth/register", json={"username": "newbie", "email": "newbie@corp.example",
                                                  "password": "A-Valid-Password-1"})
    assert r.status_code == 201
    user = db.query(User).filter_by(username="newbie").one()
    assert user.role_name == "viewer" and user.is_active is False


def test_security_headers_present(client):
    r = client.get(f"{API}/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_placeholder_secret_is_rejected():
    import pytest
    from pydantic import ValidationError

    from app.core.config import Settings
    with pytest.raises(ValidationError):
        Settings(secret_key="change-me-change-me-change-me-change-me")
