"""HTTP contract tests for the JSON API; business and database calls are isolated."""

import importlib
from types import SimpleNamespace

import pytest


api = importlib.import_module("backend.app")


class FakeQuery:
    def __init__(self, result=None):
        self.result = result

    def filter(self, *_conditions):
        return self

    def first(self):
        return self.result

    def update(self, *_args, **_kwargs):
        return 1

    def delete(self, *_args, **_kwargs):
        return 1


class FakeDatabase:
    def __init__(self, user=None):
        self.user = user

    def query(self, model):
        return FakeQuery(self.user if model is api.User else None)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture
def client():
    api.app.config.update(TESTING=True)
    before_request = api.app.before_request_funcs.get(None, [])
    api.app.before_request_funcs[None] = [
        hook for hook in before_request if hook.__name__ != "initialize_database_once"
    ]
    with api.app.test_client() as test_client:
        yield test_client
    api.app.before_request_funcs[None] = before_request
    api.app.config.update(TESTING=False)


def auth_user(role="user", mfa_enabled=False):
    return {
        "user_id": 42,
        "username": "alice",
        "email": "alice@example.test",
        "role": role,
        "mfa_enabled": mfa_enabled,
        "mfa_verified": mfa_enabled,
    }


def authenticate_client(client, monkeypatch, *, role="user", mfa_enabled=False):
    monkeypatch.setattr(api, "validate_session", lambda _token: auth_user(role, mfa_enabled))
    client.set_cookie(api.AUTH_COOKIE, "opaque-session-token")


def test_health_and_unauthenticated_session_contracts(client):
    assert client.get("/health").status_code == 200
    session = client.get("/api/auth/session")
    assert session.status_code == 401
    assert session.json == {"authenticated": False}
    assert client.post("/api/account/password", json={}).status_code == 401
    assert client.post("/api/account/mfa/enrollment", json={}).status_code == 401


def test_registration_contract(client, monkeypatch):
    assert client.post("/register", data="not-json", content_type="text/plain").status_code == 400
    mismatch = client.post("/register", json={
        "username": "alice", "email": "alice@example.test", "password": "long passphrase",
        "password_confirm": "another passphrase",
    })
    assert mismatch.status_code == 400

    monkeypatch.setattr(api, "register_user", lambda *_args: {
        "success": True, "message": "Compte créé.", "user_id": 42,
    })
    created = client.post("/register", json={
        "username": "alice", "email": "alice@example.test", "password": "long passphrase",
        "password_confirm": "long passphrase",
    })
    assert created.status_code == 201
    assert created.json["success"] is True
    assert created.headers["Cache-Control"] == "no-store"


def test_login_session_and_logout_contracts(client, monkeypatch):
    monkeypatch.setattr(api, "authenticate_user", lambda **_kwargs: {
        "success": False, "mfa_required": True, "errors": ["Second facteur requis"],
    })
    challenge = client.post("/login", json={"username": "alice", "password": "secret"})
    assert challenge.status_code == 200
    assert challenge.json["mfa_required"] is True
    assert not any(api.AUTH_COOKIE in value for value in challenge.headers.getlist("Set-Cookie"))

    monkeypatch.setattr(api, "authenticate_user", lambda **_kwargs: {
        "success": True, "session_token": "opaque-session-token",
        "user": {"id": 42, "username": "alice", "email": "alice@example.test", "role": "user"},
    })
    signed_in = client.post("/login", json={"username": "alice", "password": "secret", "totp_code": "123456"})
    assert signed_in.status_code == 200
    assert "session_token" not in signed_in.json
    cookie = next(value for value in signed_in.headers.getlist("Set-Cookie") if value.startswith(f"{api.AUTH_COOKIE}="))
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie

    monkeypatch.setattr(api, "validate_session", lambda _token: auth_user(mfa_enabled=True))
    current = client.get("/api/auth/session")
    assert current.status_code == 200
    assert current.json["user"]["mfa_enabled"] is True

    calls = []
    monkeypatch.setattr(api, "logout_user", lambda token: calls.append(token) or {"success": True})
    signed_out = client.post("/api/auth/logout", json={})
    assert signed_out.status_code == 200
    assert calls == ["opaque-session-token"]
    assert any("Max-Age=0" in value for value in signed_out.headers.getlist("Set-Cookie"))


def test_password_validation_reset_request_and_completion(client, monkeypatch):
    monkeypatch.setattr(api, "validate_password", lambda *_args: {"valid": False, "errors": ["Trop faible"]})
    assert client.post("/api/validate-password", json={"password": "weak"}).json["valid"] is False

    monkeypatch.setattr(api, "request_password_reset", lambda *_args: {
        "success": True, "message": "Si le compte existe, les instructions ont été envoyées.",
    })
    assert client.post("/password-reset", json={"identifier": "alice"}).status_code == 200

    monkeypatch.setattr(api, "complete_password_reset", lambda *_args: {
        "success": True, "message": "Mot de passe réinitialisé.",
    })
    completed = client.post("/password-reset/confirm", json={
        "token": "reset-token", "new_password": "new long passphrase", "totp_code": "123456",
    })
    assert completed.status_code == 200
    assert completed.json["success"] is True


def test_password_change_requires_session_and_returns_json(client, monkeypatch):
    authenticate_client(client, monkeypatch)
    monkeypatch.setattr(api, "change_password", lambda *_args: {
        "success": True, "message": "Mot de passe changé avec succès.",
    })
    monkeypatch.setattr(api, "get_db_session", lambda: FakeDatabase())
    response = client.post("/api/account/password", json={
        "current_password": "old passphrase", "new_password": "new long passphrase",
    })
    assert response.status_code == 200
    assert response.json["success"] is True


def test_mfa_enrollment_and_confirmation_contracts(client, monkeypatch):
    authenticate_client(client, monkeypatch)
    monkeypatch.setattr(api, "is_mfa_enabled", lambda _user_id: False)
    monkeypatch.setattr(api, "check_rate_limit", lambda *_args: {"allowed": True})
    monkeypatch.setattr(api, "record_login_attempt", lambda *_args: None)
    monkeypatch.setattr(api, "enroll_mfa", lambda *_args: {
        "secret": "TESTSECRET", "qr_code_uri": "otpauth://totp/test", "recovery_codes": ["AAAA-BBBB"],
    })
    enrollment = client.post("/api/account/mfa/enrollment", json={})
    assert enrollment.status_code == 200
    assert enrollment.json["secret"] == "TESTSECRET"
    assert enrollment.json["recovery_codes"] == ["AAAA-BBBB"]
    assert enrollment.headers["Cache-Control"] == "no-store"

    monkeypatch.setattr(api, "validate_mfa_enrollment", lambda _user_id, code: code == "123456")
    assert client.post("/api/account/mfa/enrollment/confirm", json={"totp_code": "000000"}).status_code == 400
    confirmed = client.post("/api/account/mfa/enrollment/confirm", json={"totp_code": "123456"})
    assert confirmed.status_code == 200
    assert confirmed.json["success"] is True


def test_mfa_reenrollment_after_recovery_requires_a_fresh_login(client, monkeypatch):
    client.set_cookie(api.AUTH_COOKIE, "restricted-session-token")
    calls = 0

    def validate(token):
        nonlocal calls
        calls += 1
        return auth_user() if calls == 1 and token == "restricted-session-token" else None

    monkeypatch.setattr(api, "validate_session", validate)
    monkeypatch.setattr(api, "check_rate_limit", lambda *_args: {"allowed": True})
    monkeypatch.setattr(api, "record_login_attempt", lambda *_args: None)
    monkeypatch.setattr(api, "validate_mfa_enrollment", lambda *_args: True)
    response = client.post("/api/account/mfa/enrollment/confirm", json={"totp_code": "123456"})
    assert response.status_code == 200
    assert response.json["reauthentication_required"] is True
    assert any("Max-Age=0" in value for value in response.headers.getlist("Set-Cookie"))


def test_mfa_disable_requires_password_and_a_valid_factor(client, monkeypatch):
    authenticate_client(client, monkeypatch, mfa_enabled=True)
    user = SimpleNamespace(id=42, is_active=True, mfa_enabled=True, password_hash="hashed")
    monkeypatch.setattr(api, "get_db_session", lambda: FakeDatabase(user))
    monkeypatch.setattr(api, "verify_password", lambda password, _hashed: password == "current password")
    monkeypatch.setattr(api, "get_totp_secret", lambda _user_id: "TESTSECRET")
    monkeypatch.setattr(api, "verify_totp_code", lambda _secret, code, _user_id: code == "123456")
    monkeypatch.setattr(api, "check_rate_limit", lambda *_args: {"allowed": True})
    monkeypatch.setattr(api, "record_login_attempt", lambda *_args: None)

    invalid = client.post("/api/account/mfa/disable", json={
        "current_password": "wrong", "totp_code": "123456",
    })
    assert invalid.status_code == 400
    disabled = client.post("/api/account/mfa/disable", json={
        "current_password": "current password", "totp_code": "123456",
    })
    assert disabled.status_code == 200
    assert disabled.json["success"] is True
    assert user.mfa_enabled is False


def test_mfa_recovery_endpoints_are_public_and_return_neutral_json(client, monkeypatch):
    user = SimpleNamespace(id=42, is_active=True, mfa_enabled=True)
    monkeypatch.setattr(api, "get_db_session", lambda: FakeDatabase(user))
    monkeypatch.setattr(api, "check_rate_limit", lambda *_args: {"allowed": True})
    monkeypatch.setattr(api, "record_login_attempt", lambda *_args: None)
    calls = []
    monkeypatch.setattr(api, "request_mfa_recovery", lambda *_args: calls.append("request") or True)
    requested = client.post("/mfa/recovery/request", json={"identifier": "alice"})
    assert requested.status_code == 200
    assert "Si le compte peut être récupéré" in requested.json["message"]
    assert calls == ["request"]

    monkeypatch.setattr(api, "complete_mfa_recovery", lambda user_id, *_args: user_id is None)
    confirmed = client.post("/mfa/recovery/confirm", json={
        "token": "recovery-token", "current_password": "current password",
    })
    assert confirmed.status_code == 200
    assert confirmed.json["success"] is True
    assert any("Max-Age=0" in value for value in confirmed.headers.getlist("Set-Cookie"))


def test_admin_password_reset_requires_an_admin_session(client, monkeypatch):
    authenticate_client(client, monkeypatch, role="user")
    denied = client.post("/admin/users/7/password-reset", json={})
    assert denied.status_code == 403

    authenticate_client(client, monkeypatch, role="admin")
    monkeypatch.setattr(api, "request_password_reset", lambda *_args, **_kwargs: {"success": True})
    allowed = client.post("/admin/users/7/password-reset", json={})
    assert allowed.status_code == 200
    assert allowed.json["success"] is True
