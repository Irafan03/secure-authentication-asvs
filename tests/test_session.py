from datetime import datetime, timedelta

import auth_login


def test_session_created_after_successful_login(p2_user):
    result = auth_login.authenticate_user(
        p2_user["username"], p2_user["password"], "198.51.100.40"
    )
    assert result["success"] is True
    assert len(result["session_token"]) == 64
    assert auth_login.validate_session(result["session_token"])["user_id"] == p2_user["id"]


def test_invalid_and_expired_session_tokens_are_rejected(p2_user, mysql_test_db):
    assert auth_login.validate_session("not-a-session-token") is None

    token = auth_login.create_session(p2_user["id"], "198.51.100.41")
    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET expires_at = %s WHERE session_token = %s",
            (datetime.now() - timedelta(seconds=1), token),
        )
        conn.commit()
    assert auth_login.validate_session(token) is None


def test_logout_revokes_session_and_prevents_reuse(p2_user):
    token = auth_login.create_session(p2_user["id"], "198.51.100.42")
    result = auth_login.logout_user(token)
    assert result["success"] is True
    assert auth_login.validate_session(token) is None


def test_login_issues_a_fresh_session_identifier(p2_user):
    first = auth_login.authenticate_user(
        p2_user["username"], p2_user["password"], "198.51.100.43"
    )
    second = auth_login.authenticate_user(
        p2_user["username"], p2_user["password"], "198.51.100.43"
    )
    assert first["success"] and second["success"]
    assert first["session_token"] != second["session_token"]


def test_require_valid_session_checks_owner(p2_user):
    token = auth_login.create_session(p2_user["id"], "198.51.100.44")
    assert auth_login.require_valid_session(token, p2_user["id"])["user_id"] == p2_user["id"]
    try:
        auth_login.require_valid_session(token, p2_user["id"] + 1)
    except auth_login.AccessDeniedError:
        pass
    else:
        raise AssertionError("A valid session must not authorize a different user")
