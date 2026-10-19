import logging

import auth_login
import auth_register


def _quiet_login_setup(monkeypatch):
    monkeypatch.setattr(auth_login, "cleanup_old_attempts", lambda: None)
    monkeypatch.setattr(auth_login, "cleanup_expired_sessions", lambda: None)
    monkeypatch.setattr(auth_login, "check_rate_limit", lambda *_: {"allowed": True, "delay": 0})
    monkeypatch.setattr(auth_login, "record_login_attempt", lambda *args: None)


def test_login_accepts_password_verified_from_mysql_hash(p2_user):
    result = auth_login.authenticate_user(
        p2_user["username"], p2_user["password"], "198.51.100.10"
    )
    assert result["success"] is True
    assert result["session_token"]
    assert result["user"]["id"] == p2_user["id"]
    assert auth_login.validate_session(result["session_token"])


def test_login_rejects_wrong_password_with_generic_error(p2_user):
    result = auth_login.authenticate_user(
        p2_user["username"], "wrong-password", "198.51.100.11"
    )
    assert result["success"] is False
    assert result["errors"] == ["Nom d'utilisateur ou mot de passe incorrect"]


def test_login_rejects_unknown_user_with_same_error(p2_user):
    result = auth_login.authenticate_user(
        f"{p2_user['username']}_missing", p2_user["password"], "198.51.100.12"
    )
    assert result["success"] is False
    assert result["errors"] == ["Nom d'utilisateur ou mot de passe incorrect"]


def test_database_lookup_error_is_generic_and_not_logged(monkeypatch, caplog):
    _quiet_login_setup(monkeypatch)

    def database_error():
        raise RuntimeError("sensitive database detail")

    monkeypatch.setattr(auth_register, "get_connection", database_error)
    with caplog.at_level(logging.ERROR):
        result = auth_login.authenticate_user("any-user", "secret-password", "198.51.100.13")

    assert result["success"] is False
    assert result["errors"] == ["Nom d'utilisateur ou mot de passe incorrect"]
    assert "sensitive database detail" not in caplog.text
    assert "secret-password" not in caplog.text


def test_login_sql_uses_a_parameterized_username_query(monkeypatch):
    captured = {}

    class Cursor:
        def execute(self, query, params):
            captured["query"] = query
            captured["params"] = params

        def fetchone(self):
            return None

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def cursor(self, **_):
            return Cursor()

    monkeypatch.setattr(auth_register, "get_connection", lambda: Connection())
    auth_register.get_user_by_username("name' OR 1=1 --")
    assert captured["params"] == ("name' OR 1=1 --",)
    assert "%s" in captured["query"]
