from datetime import datetime, timedelta
import uuid

import auth_login
from config import RATE_LIMIT_USER_IP_WINDOW


def test_account_limit_blocks_after_configured_threshold(p2_user, monkeypatch):
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USER_IP_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USER_IP_LOCKOUT", timedelta(minutes=10))
    monkeypatch.setattr(auth_login, "RATE_LIMIT_IP_MAX_ATTEMPTS", 100)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USERNAME_MAX_ATTEMPTS", 100)
    ip = f"198.51.100.{20 + uuid.uuid4().int % 200}"
    for _ in range(2):
        auth_login.record_login_attempt(p2_user["username"], ip, False)

    limited = auth_login.check_rate_limit(p2_user["username"], ip)
    assert limited["allowed"] is False
    assert limited["unlock_time"] is not None


def test_old_attempts_expire_without_waiting(p2_user, mysql_test_db, monkeypatch):
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USER_IP_MAX_ATTEMPTS", 1)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_IP_MAX_ATTEMPTS", 100)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USERNAME_MAX_ATTEMPTS", 100)
    ip = f"198.51.100.{20 + uuid.uuid4().int % 200}"
    auth_login.record_login_attempt(p2_user["username"], ip, False)
    assert not auth_login.check_rate_limit(p2_user["username"], ip)["allowed"]

    expired_at = datetime.now() - RATE_LIMIT_USER_IP_WINDOW - timedelta(seconds=1)
    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE login_attempts SET attempted_at = %s WHERE identifier = %s AND identifier_type = 'user_ip'",
            (expired_at, f"{p2_user['username']}:{ip}"),
        )
        conn.commit()

    assert auth_login.check_rate_limit(p2_user["username"], ip)["allowed"] is True


def test_ip_limit_cannot_be_avoided_by_changing_username(mysql_test_db, monkeypatch):
    monkeypatch.setattr(auth_login, "RATE_LIMIT_IP_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USER_IP_MAX_ATTEMPTS", 100)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USERNAME_MAX_ATTEMPTS", 100)
    ip = f"198.51.100.{20 + uuid.uuid4().int % 200}"
    auth_login.record_login_attempt("first-name", ip, False)
    auth_login.record_login_attempt("second-name", ip, False)

    result = auth_login.check_rate_limit("third-name", ip)
    assert result["allowed"] is False
    assert "adresse IP" in result["reason"]


def test_progressive_delay_uses_attempt_count(mysql_test_db, monkeypatch):
    username = f"p2_{uuid.uuid4().hex[:12]}"
    ip = f"198.51.100.{20 + uuid.uuid4().int % 200}"
    monkeypatch.setattr(auth_login, "RATE_LIMIT_IP_MAX_ATTEMPTS", 100)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USER_IP_MAX_ATTEMPTS", 100)
    monkeypatch.setattr(auth_login, "RATE_LIMIT_USERNAME_MAX_ATTEMPTS", 100)
    auth_login.record_login_attempt(username, ip, False)

    result = auth_login.check_rate_limit(username, ip)
    assert result["allowed"] is True
    assert result["delay"] > 0

    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM login_attempts WHERE identifier LIKE %s", (f"{username}%",))
        conn.commit()
