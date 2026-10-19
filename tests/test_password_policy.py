from unittest.mock import MagicMock

import pytest

import auth_register
from config import LOCAL_COMMON_PASSWORDS_MIN


@pytest.fixture(autouse=True)
def offline_hibp(monkeypatch):
    # These tests exercise local rules; HIBP is covered separately.
    monkeypatch.setattr(auth_register, "check_password_pwned", lambda _password: True)


def test_local_password_list_has_enough_distinct_nonempty_entries():
    passwords = auth_register.load_common_passwords()
    assert len(passwords) >= LOCAL_COMMON_PASSWORDS_MIN
    assert all(password and password == password.strip().casefold() for password in passwords)


def test_common_password_is_rejected_case_insensitively():
    result = auth_register.validate_password("PaSsWoRd")
    assert result["valid"] is False
    assert any("couramment utilisés" in error for error in result["errors"])


def test_missing_password_list_fails_closed(monkeypatch):
    monkeypatch.setattr(auth_register, "_common_passwords_set", None)

    def missing_file(*_args, **_kwargs):
        raise FileNotFoundError("test-only missing list")

    monkeypatch.setattr("builtins.open", missing_file)
    result = auth_register.validate_password("jhqwpzvm")
    assert result["valid"] is False
    assert any("liste locale" in error.lower() for error in result["errors"])


@pytest.mark.parametrize("password", ["short7", "short7x"])
def test_passwords_shorter_than_eight_characters_are_rejected(password):
    result = auth_register.validate_password(password)
    assert result["valid"] is False
    assert any("8 caractères" in error for error in result["errors"])


@pytest.mark.parametrize("password", ["jhqwpzvm", "jhqwpzvmx", "jhqwpzvmxqwert"])
def test_eight_and_longer_noncommon_passwords_need_no_composition(password):
    assert password.casefold() not in auth_register.load_common_passwords()
    result = auth_register.validate_password(password)
    assert result["valid"] is True, result["errors"]


def test_registration_enforces_minimum_server_side(monkeypatch):
    cursor = MagicMock()
    cursor.fetchone.return_value = None
    cursor.lastrowid = 123
    connection = MagicMock()
    connection.cursor.return_value = cursor
    monkeypatch.setattr(auth_register, "get_connection", lambda: _connection_context(connection))

    rejected = auth_register.register_user("new-user", "new@example.com", "short7x")
    assert rejected["success"] is False
    assert not any("INSERT INTO users" in str(call) for call in cursor.execute.call_args_list)

    accepted = auth_register.register_user("new-user", "new@example.com", "jhqwpzvm")
    assert accepted["success"] is True
    insert_call = next(call for call in cursor.execute.call_args_list if "INSERT INTO users" in call.args[0])
    assert insert_call.args[1][2].startswith("$argon2id$")
    assert insert_call.args[1][2] != "jhqwpzvm"


def _connection_context(connection):
    class Context:
        def __enter__(self):
            return connection

        def __exit__(self, *_args):
            return False

    return Context()


def _change_password_cursor(monkeypatch, stored_password):
    cursor = MagicMock()
    cursor.fetchone.return_value = ("member", auth_register.hash_password(stored_password))
    connection = MagicMock()
    connection.cursor.return_value = cursor
    monkeypatch.setattr(auth_register, "get_connection", lambda: _connection_context(connection))
    return cursor, connection


def test_password_change_stores_only_hash_and_revokes_sessions(monkeypatch):
    old_password = "current-old-password-42"
    new_password = "jhqwpzvm"
    cursor, connection = _change_password_cursor(monkeypatch, old_password)

    result = auth_register.change_password(42, old_password, new_password)
    assert result["success"] is True
    updates = [call for call in cursor.execute.call_args_list if call.args[0].startswith("UPDATE ")]
    password_update = next(call for call in updates if "UPDATE users SET password_hash" in call.args[0])
    stored_hash = password_update.args[1][0]
    assert stored_hash.startswith("$argon2id$")
    assert auth_register.verify_password(new_password, stored_hash)
    assert new_password not in password_update.args[1]
    assert any("UPDATE sessions SET invalidated = 1" in call.args[0] for call in updates)
    connection.commit.assert_called_once()


def test_wrong_old_password_does_not_update_hash_or_revoke_sessions(monkeypatch):
    cursor, connection = _change_password_cursor(monkeypatch, "the-actual-old-password")
    result = auth_register.change_password(42, "incorrect-old-password", "jhqwpzvm")

    assert result["success"] is False
    assert any("incorrect" in error.lower() for error in result["errors"])
    assert not any(call.args[0].startswith("UPDATE ") for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


def test_password_change_rejects_short_new_password_without_updates(monkeypatch):
    cursor, connection = _change_password_cursor(monkeypatch, "the-actual-old-password")
    result = auth_register.change_password(42, "the-actual-old-password", "short7x")

    assert result["success"] is False
    assert any("8 caractères" in error for error in result["errors"])
    assert not any(call.args[0].startswith("UPDATE ") for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()
