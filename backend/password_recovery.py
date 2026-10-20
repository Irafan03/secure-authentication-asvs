"""Password reset and MFA loss recovery flows (SQLAlchemy only)."""
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta

from .auth_login import check_rate_limit, record_login_attempt
from .auth_register import validate_password, hash_password, verify_password
from .config import PASSWORD_RESET_TOKEN_TTL, PASSWORD_RESET_URL_BASE, APP_PUBLIC_BASE_URL
from .models import get_db_session, User, PasswordResetToken, Session as DbSession, MfaSecret, MfaRecoveryCode, TotpUsedCode, MfaReenrollment
from .notifications import get_notification_service

logger = logging.getLogger(__name__)


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _issue(user, ip_address, initiated_by="user", initiated_by_user_id=None, purpose="password"):
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    db = get_db_session()
    try:
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None)
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
        db.query(PasswordResetToken).filter(PasswordResetToken.expires_at < now).delete(synchronize_session=False)
        record = PasswordResetToken(
            user_id=user.id, token_hash=_hash_token(token), purpose=purpose,
            created_at=now, expires_at=now + PASSWORD_RESET_TOKEN_TTL,
            initiated_by=initiated_by, initiated_by_user_id=initiated_by_user_id
        )
        db.add(record)
        db.commit()
        return token, user.email, user.username
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def request_password_reset(identifier, ip_address, initiated_by="user", initiated_by_user_id=None, target_user_id=None):
    """Always returns the same public result, whether or not an account exists."""
    lookup_identifier = (identifier or "").strip()
    identifier = lookup_identifier.lower()
    allowed = check_rate_limit(identifier or "", ip_address or "unknown")
    record_login_attempt(identifier or "", ip_address or "unknown", False)
    if not allowed.get("allowed"):
        return {"success": True, "message": "Si le compte existe, les instructions ont été envoyées."}
    db = get_db_session()
    try:
        query = db.query(User).filter(User.is_active.is_(True))
        if target_user_id is not None:
            user = query.filter(User.id == target_user_id).first()
        else:
            user = query.filter((User.username == lookup_identifier) | (User.email == identifier)).first()
        if user:
            token, email, username = _issue(user, ip_address, initiated_by, initiated_by_user_id)
            link = f"{PASSWORD_RESET_URL_BASE}?token={token}"
            ttl_minutes = max(1, int(PASSWORD_RESET_TOKEN_TTL.total_seconds() // 60))
            get_notification_service().notify_password_reset(email, username, link, initiated_by == "admin", ttl_minutes)
        # Same expensive dummy hash verification on both account paths.
        from .auth_login import _get_dummy_hash, ph
        try:
            ph.verify(_get_dummy_hash(), "dummy_password")
        except Exception:
            pass
        logger.info("Password reset request processed at %s (initiator=%s, actor=%s, target=%s)", datetime.now(), initiated_by,
                    initiated_by_user_id,
                    user.id if user else "unknown")
        return {"success": True, "message": "Si le compte existe, les instructions ont été envoyées."}
    except Exception:
        logger.exception("Password reset request failed")
        return {"success": True, "message": "Si le compte existe, les instructions ont été envoyées."}
    finally:
        db.close()


def complete_password_reset(token, new_password, ip_address, totp_code=None, recovery_code=None):
    from .auth_mfa import get_totp_secret, verify_totp_code, verify_recovery_code
    digest = _hash_token(token or "")
    db = get_db_session()
    identifier = digest
    allowed = check_rate_limit(identifier, ip_address or "unknown")
    if not allowed.get("allowed"):
        record_login_attempt(identifier, ip_address or "unknown", False)
        return {"success": False, "errors": ["Jeton invalide ou expiré"]}
    try:
        now = datetime.now()
        record = db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == digest,
            PasswordResetToken.purpose == "password",
            PasswordResetToken.used_at.is_(None), PasswordResetToken.expires_at > now
        ).with_for_update().first()
        if not record or not hmac.compare_digest(record.token_hash, digest):
            record_login_attempt(identifier, ip_address or "unknown", False)
            return {"success": False, "errors": ["Jeton invalide ou expiré"]}
        user = db.query(User).filter(User.id == record.user_id).first()
        if not user:
            record_login_attempt(identifier, ip_address or "unknown", False)
            return {"success": False, "errors": ["Jeton invalide ou expiré"]}
        if user.mfa_enabled:
            valid_factor = False
            if totp_code:
                secret = get_totp_secret(user.id)
                valid_factor = bool(secret and verify_totp_code(secret, totp_code, user.id))
            elif recovery_code:
                valid_factor = verify_recovery_code(user.id, recovery_code)
            if not valid_factor:
                record_login_attempt(user.username, ip_address or "unknown", False)
                return {"success": False, "errors": ["Un second facteur valide est requis"]}
        validation = validate_password(new_password, user.username)
        if not validation["valid"]:
            return {"success": False, "errors": validation["errors"]}
        if verify_password(new_password, user.password_hash):
            return {"success": False, "errors": ["Le nouveau mot de passe doit être différent de l'ancien"]}
        user.password_hash = hash_password(new_password)
        record.used_at = now
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.purpose == "password",
            PasswordResetToken.id != record.id,
            PasswordResetToken.used_at.is_(None)
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
        db.query(DbSession).filter(DbSession.user_id == user.id).delete(synchronize_session=False)
        db.commit()
        record_login_attempt(user.username, ip_address or "unknown", True)
        get_notification_service().notify_password_changed(user.email, user.username, ip_address or "unknown")
        return {"success": True, "message": "Mot de passe réinitialisé. Veuillez vous reconnecter."}
    except Exception:
        db.rollback()
        logger.exception("Password reset completion failed")
        return {"success": False, "errors": ["Erreur interne"]}
    finally:
        db.close()


def request_mfa_recovery(user_id, ip_address):
    """Issue a rate-limited mailbox confirmation for an account with MFA enabled."""
    allowed = check_rate_limit(f"mfa:{user_id}", ip_address or "unknown")
    record_login_attempt(f"mfa:{user_id}", ip_address or "unknown", False)
    if not allowed.get("allowed"):
        return False
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == user_id, User.is_active.is_(True), User.mfa_enabled.is_(True)).first()
        if not user:
            return False
        token, email, username = _issue(user, ip_address, purpose="mfa_recovery")
        get_notification_service().notify_mfa_recovery(
            email, username, f"{APP_PUBLIC_BASE_URL.rstrip('/')}/mfa/recovery/confirm?token={token}")
        return True
    finally:
        db.close()


def complete_mfa_recovery(user_id, token, current_password, ip_address):
    digest = _hash_token(token or "")
    db = get_db_session()
    try:
        now = datetime.now()
        record_query = db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == digest,
            PasswordResetToken.purpose == "mfa_recovery", PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now
        )
        if user_id is not None:
            record_query = record_query.filter(PasswordResetToken.user_id == user_id)
        record = record_query.with_for_update().first()
        if user_id is None and record:
            user_id = record.user_id
        user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first() if user_id is not None else None
        if not user or not record or not hmac.compare_digest(record.token_hash, digest) or not verify_password(current_password, user.password_hash):
            record_login_attempt(f"mfa:{user_id}", ip_address or "unknown", False)
            return False
        record.used_at = now
        user.mfa_enabled = False
        db.merge(MfaReenrollment(user_id=user_id, created_at=now))
        db.query(MfaSecret).filter(MfaSecret.user_id == user_id).delete(synchronize_session=False)
        db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user_id).delete(synchronize_session=False)
        db.query(TotpUsedCode).filter(TotpUsedCode.user_id == user_id).delete(synchronize_session=False)
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id, PasswordResetToken.purpose == "mfa_recovery",
            PasswordResetToken.id != record.id, PasswordResetToken.used_at.is_(None)
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
        db.query(DbSession).filter(DbSession.user_id == user_id).delete(synchronize_session=False)
        db.commit()
        record_login_attempt(user.username, ip_address or "unknown", True)
        get_notification_service().notify_mfa_reset(user.email, user.username)
        return True
    except Exception:
        db.rollback()
        logger.exception("MFA recovery failed")
        return False
    finally:
        db.close()
