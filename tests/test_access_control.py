from datetime import datetime, timedelta

import pytest

import auth_login
import auth_mfa
import auth_register


def test_private_backend_operation_rejects_missing_or_invalid_session(p2_user):
    with pytest.raises(auth_login.AccessDeniedError):
        auth_mfa.enroll_mfa(p2_user["id"], p2_user["username"])
    with pytest.raises(auth_login.AccessDeniedError):
        auth_mfa.enroll_mfa(
            p2_user["id"], p2_user["username"], session_token="invalid-token"
        )


def test_private_backend_operation_accepts_session_for_same_user(p2_user, mysql_test_db):
    token = auth_login.create_session(p2_user["id"], "198.51.100.50")
    result = auth_mfa.enroll_mfa(
        p2_user["id"], p2_user["username"], session_token=token
    )
    assert result["success"] is True
    assert result["secret"]
    assert result["recovery_codes"]

    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM mfa_recovery_codes WHERE user_id = %s", (p2_user["id"],))
        cursor.execute("DELETE FROM mfa_secrets WHERE user_id = %s", (p2_user["id"],))
        conn.commit()


def test_private_backend_operation_rejects_another_users_session(p2_user, mysql_test_db):
    with mysql_test_db() as conn:
        cursor = conn.cursor()
        username = f"{p2_user['username']}_other"
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, f"{username}@example.test", auth_register.hash_password("Other-user-P2-test-password")),
        )
        other_user_id = cursor.lastrowid
        conn.commit()
    token = auth_login.create_session(other_user_id, "198.51.100.51")
    with pytest.raises(auth_login.AccessDeniedError):
        auth_mfa.enroll_mfa(
            p2_user["id"], p2_user["username"], session_token=token
        )
    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (other_user_id,))
        conn.commit()


def test_expired_or_revoked_session_cannot_authorize_backend(p2_user, mysql_test_db):
    expired_token = auth_login.create_session(p2_user["id"], "198.51.100.52")
    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET expires_at = %s WHERE session_token = %s",
            (datetime.now() - timedelta(seconds=1), expired_token),
        )
        conn.commit()
    with pytest.raises(auth_login.AccessDeniedError):
        auth_mfa.enroll_mfa(
            p2_user["id"], p2_user["username"], session_token=expired_token
        )

    revoked_token = auth_login.create_session(p2_user["id"], "198.51.100.53")
    auth_login.logout_user(revoked_token)
    with pytest.raises(auth_login.AccessDeniedError):
        auth_mfa.enroll_mfa(
            p2_user["id"], p2_user["username"], session_token=revoked_token
        )
