from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend.password_recovery as recovery
from backend.auth_register import hash_password
from backend.models import Base, User, PasswordResetToken, Session as DbSession
from backend.notifications import BaseNotificationService, set_notification_service


class CapturingNotifications(BaseNotificationService):
    def __init__(self):
        self.messages = []

    def send_notification(self, recipient, subject, message, event_type):
        self.messages.append((recipient, subject, message, event_type))
        return True


@pytest.fixture
def recovery_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(recovery, "get_db_session", factory)
    monkeypatch.setattr(recovery, "check_rate_limit", lambda *_: {"allowed": True})
    monkeypatch.setattr(recovery, "record_login_attempt", lambda *args: None)
    monkeypatch.setattr(recovery, "validate_password", lambda *_: {"valid": True, "errors": []})
    monkeypatch.setattr(recovery, "verify_password", lambda pw, hashed: pw == "OldPassword123!" if hashed == "old-hash" else False)
    monkeypatch.setattr(recovery, "hash_password", lambda pw: "new-hash")
    notifications = CapturingNotifications()
    set_notification_service(notifications)
    db = factory()
    db.add(User(id=1, username="test-user", email="person@example.test", password_hash="old-hash", is_active=True, role="user", mfa_enabled=False))
    db.add(DbSession(session_token="s" * 64, user_id=1, expires_at=__import__("datetime").datetime.now() + __import__("datetime").timedelta(hours=1)))
    db.commit()
    yield factory, notifications
    db.close()
    engine.dispose()


def _token_from_notification(notifications):
    url = next(line for line in notifications.messages[-1][2].splitlines() if "token=" in line)
    return parse_qs(urlparse(url).query)["token"][0]


def test_reset_request_is_neutral_and_stores_only_hash(recovery_db):
    factory, notifications = recovery_db
    known = recovery.request_password_reset("test-user", "192.0.2.1")
    unknown = recovery.request_password_reset("missing-user", "192.0.2.1")
    assert known == unknown
    raw_token = _token_from_notification(notifications)
    db = factory()
    stored = db.query(PasswordResetToken).first()
    assert stored.token_hash != raw_token
    assert len(stored.token_hash) == 64
    assert (stored.expires_at - stored.created_at).total_seconds() == 1200
    db.close()


def test_reset_is_one_use_and_invalidates_sessions(recovery_db):
    _, notifications = recovery_db
    recovery.request_password_reset("test-user", "192.0.2.1")
    token = _token_from_notification(notifications)
    result = recovery.complete_password_reset(token, "NewPassword123!", "192.0.2.1")
    assert result["success"] is True
    assert recovery.complete_password_reset(token, "AnotherPassword123!", "192.0.2.1")["success"] is False
    factory, _ = recovery_db
    db = factory()
    assert db.query(DbSession).filter(DbSession.user_id == 1).count() == 0
    db.close()


def test_reset_admin_metadata_does_not_return_secret(recovery_db):
    factory, notifications = recovery_db
    result = recovery.request_password_reset("", "192.0.2.2", initiated_by="admin", initiated_by_user_id=9, target_user_id=1)
    assert "token" not in str(result)
    assert "token=" in notifications.messages[-1][2]
    db = factory()
    stored = db.query(PasswordResetToken).first()
    assert stored.initiated_by == "admin"
    assert stored.initiated_by_user_id == 9
    db.close()


def test_reset_does_not_bypass_enabled_mfa(recovery_db):
    factory, notifications = recovery_db
    db = factory()
    db.query(User).filter(User.id == 1).update({User.mfa_enabled: True})
    db.commit()
    db.close()
    recovery.request_password_reset("test-user", "192.0.2.1")
    token = _token_from_notification(notifications)
    result = recovery.complete_password_reset(token, "NewPassword123!", "192.0.2.1")
    assert result["success"] is False
    assert "second facteur" in result["errors"][0]
