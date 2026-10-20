"""
auth_login.py — Authentification sécurisée avec protection contre le brute force
ASVS 5.0.0 — Niveau 2
"""

import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from .auth_register import verify_password, get_user_by_username, ph
from .database import get_connection
from .models import get_db_session, LoginAttempt, Session as DbSession, User, UserDevice, MfaReenrollment
from sqlalchemy import func, or_
from .notifications import get_notification_service
from .config import (
    RATE_LIMIT_IP_MAX_ATTEMPTS, RATE_LIMIT_IP_WINDOW, RATE_LIMIT_IP_LOCKOUT,
    RATE_LIMIT_USER_IP_MAX_ATTEMPTS, RATE_LIMIT_USER_IP_WINDOW, RATE_LIMIT_USER_IP_LOCKOUT,
    RATE_LIMIT_USERNAME_MAX_ATTEMPTS, RATE_LIMIT_USERNAME_WINDOW,
    RATE_LIMIT_USERNAME_DELAY_ENABLED, RATE_LIMIT_USERNAME_DELAY_BASE,
    RATE_LIMIT_USERNAME_DELAY_MULTIPLIER,
    RATE_LIMIT_LOCKOUT_MESSAGE, INVALID_CREDENTIALS_MESSAGE,
    LOGIN_INACTIVITY_THRESHOLD, SUSPICIOUS_FAILED_ATTEMPTS_THRESHOLD,
    SESSION_DURATION, SESSION_TOKEN_LENGTH, LOGIN_ATTEMPTS_RETENTION,
    DUMMY_PASSWORD_HASH
)

logger = logging.getLogger(__name__)

# Hash factice généré au démarrage pour protection timing attack (6.3.8)
_DUMMY_HASH = None

def _get_dummy_hash() -> str:
    """Génère ou retourne le hash factice pour les utilisateurs inexistants."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = ph.hash("dummy_password_for_timing_protection")
    return _DUMMY_HASH

class AuthenticationError(Exception):
    """Exception pour les erreurs d'authentification."""
    pass

class AccountLockedError(AuthenticationError):
    """Exception pour les comptes temporairement bloqués."""
    pass

class AccessDeniedError(AuthenticationError):
    """Raised when a protected backend operation has no valid session."""
    pass

def require_valid_session(session_token: Optional[str], user_id: Optional[int] = None) -> Dict[str, Any]:
    """Require an active session, optionally owned by the requested user.

    This helper is usable by backend services without a Flask dependency.
    Invalid, expired, revoked, inactive-user, and mismatched-user sessions
    have the same public failure.
    """
    session_data = validate_session(session_token) if session_token else None
    if not session_data or (user_id is not None and session_data.get("user_id") != user_id):
        raise AccessDeniedError("Authentication required")
    return session_data

def generate_session_token() -> str:
    """
    Génère un token de session cryptographiquement sûr.
    
    Returns:
        Token de session hexadécimal
    """
    return secrets.token_hex(SESSION_TOKEN_LENGTH)

def record_login_attempt(username: str, ip_address: str, success: bool) -> None:
    """
    Enregistre une tentative de connexion pour le rate limiting via l'ORM.
    """
    try:
        session = get_db_session()
        try:
            # Enregistrement par IP
            session.add(LoginAttempt(
                identifier=ip_address,
                success=success,
                ip_address=ip_address,
                identifier_type='ip'
            ))
            # Enregistrement par (username, IP) si username fourni
            if username:
                user_ip_identifier = f"{username}:{ip_address}"
                session.add(LoginAttempt(
                    identifier=user_ip_identifier,
                    success=success,
                    ip_address=ip_address,
                    identifier_type='user_ip'
                ))
                # Enregistrement par username seul
                session.add(LoginAttempt(
                    identifier=username,
                    success=success,
                    ip_address=ip_address,
                    identifier_type='username'
                ))
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement de la tentative de connexion: {e}")

def check_rate_limit(username: str, ip_address: str) -> Dict[str, Any]:
    """
    Vérifie le rate limiting selon ASVS 6.3.1 (via ORM).
    """
    try:
        session = get_db_session()
        try:
            current_time = datetime.now()
            # 1. Vérifier rate limit par IP
            ip_cutoff = current_time - RATE_LIMIT_IP_WINDOW
            ip_res = session.query(func.count(LoginAttempt.id),func.max(LoginAttempt.attempted_at)
            ).filter(
                LoginAttempt.identifier == ip_address,
                LoginAttempt.identifier_type == 'ip',
                LoginAttempt.attempted_at > ip_cutoff,
                LoginAttempt.success == False
            ).first()
            ip_failed_attempts = ip_res[0] if ip_res and ip_res[0] else 0
            ip_last_attempt = ip_res[1] if ip_res and ip_res[1] else None
            if ip_failed_attempts >= RATE_LIMIT_IP_MAX_ATTEMPTS and ip_last_attempt:
                unlock_time = ip_last_attempt + RATE_LIMIT_IP_LOCKOUT
                if current_time < unlock_time:
                    return {
                        'allowed': False,
                        'reason': f"{RATE_LIMIT_LOCKOUT_MESSAGE}",
                        'unlock_time': unlock_time,
                        'delay': 0
                    }
            # 2. Vérifier rate limit par (username, IP)
            user_ip_identifier = f"{username}:{ip_address}"
            user_ip_cutoff = current_time - RATE_LIMIT_USER_IP_WINDOW
            user_ip_res = session.query(
                func.count(LoginAttempt.id),
                func.max(LoginAttempt.attempted_at)
            ).filter(
                LoginAttempt.identifier == user_ip_identifier,
                LoginAttempt.identifier_type == 'user_ip',
                LoginAttempt.attempted_at > user_ip_cutoff,
                LoginAttempt.success == False
            ).first()
            
            user_ip_failed_attempts = user_ip_res[0] if user_ip_res and user_ip_res[0] else 0
            user_ip_last_attempt = user_ip_res[1] if user_ip_res and user_ip_res[1] else None
            
            if user_ip_failed_attempts >= RATE_LIMIT_USER_IP_MAX_ATTEMPTS and user_ip_last_attempt:
                unlock_time = user_ip_last_attempt + RATE_LIMIT_USER_IP_LOCKOUT
                if current_time < unlock_time:
                    return {
                        'allowed': False,
                        'reason': f"{RATE_LIMIT_LOCKOUT_MESSAGE}. Réessayez après {unlock_time.strftime('%H:%M:%S')}",
                        'unlock_time': unlock_time,
                        'delay': 0
                    }
            
            # 3. Vérifier rate limit par username (seuil élevé + délai progressif)
            username_cutoff = current_time - RATE_LIMIT_USERNAME_WINDOW
            username_failed_attempts = session.query(
                func.count(LoginAttempt.id)
            ).filter(
                LoginAttempt.identifier == username,
                LoginAttempt.identifier_type == 'username',
                LoginAttempt.attempted_at > username_cutoff,
                LoginAttempt.success == False
            ).scalar() or 0
            
            # Calculer le délai progressif si activé
            delay = 0
            if RATE_LIMIT_USERNAME_DELAY_ENABLED and username_failed_attempts > 0:
                # Délai exponentiel: base * (multiplier ^ failed_attempts)
                delay = RATE_LIMIT_USERNAME_DELAY_BASE * (RATE_LIMIT_USERNAME_DELAY_MULTIPLIER ** username_failed_attempts)
                # Limiter le délai max à 30 secondes
                delay = min(delay, 30.0)
            
            # Seuil très élevé pour éviter le DoS sur compte légitime
            if username_failed_attempts >= RATE_LIMIT_USERNAME_MAX_ATTEMPTS:
                unlock_time = current_time + timedelta(hours=1)
                return {
                    'allowed': False,
                    'reason': f"{RATE_LIMIT_LOCKOUT_MESSAGE}. Réessayez après {unlock_time.strftime('%H:%M:%S')}",
                    'unlock_time': unlock_time,
                    'delay': 0
                }
            
            return {
                'allowed': True,
                'reason': None,
                'unlock_time': None,
                'delay': delay
            }
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du rate limit: {e}")
        # En cas d'erreur, autoriser mais logger
        return {'allowed': True, 'reason': None, 'unlock_time': None, 'delay': 0}

def cleanup_old_attempts() -> None:
    """Nettoie les anciennes tentatives de connexion (via ORM)."""
    try:
        session = get_db_session()
        try:
            cutoff_time = datetime.now() - LOGIN_ATTEMPTS_RETENTION
            deleted_count = session.query(LoginAttempt).filter(
                LoginAttempt.attempted_at < cutoff_time
            ).delete()
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"Nettoyé {deleted_count} anciennes tentatives de connexion")
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage des tentatives: {e}")

def create_session(user_id: int, ip_address: str = None, mfa_verified: bool = False) -> str:
    """
    Crée une nouvelle session pour un utilisateur (via ORM).
    
    ASVS 6.3.3, 6.5.1: Le MFA doit être vérifié avant l'émission de la session.
    
    Args:
        user_id: ID de l'utilisateur
        ip_address: Adresse IP du client
        mfa_verified: True si le MFA a été vérifié
        
    Returns:
        Token de session
        
    Raises:
        AuthenticationError: Si la création de session échoue
    """
    try:
        session_token = generate_session_token()
        expires_at = datetime.now() + SESSION_DURATION
        
        session = get_db_session()
        try:
            new_session = DbSession(
                session_token=session_token,
                user_id=user_id,
                expires_at=expires_at,
                ip_address=ip_address,
                mfa_verified=mfa_verified
            )
            session.add(new_session)
            session.commit()
            
            logger.info(f"Session créée pour l'utilisateur ID {user_id} (MFA: {mfa_verified})")
            return session_token
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Erreur lors de la création de session pour l'utilisateur {user_id}: {e}")
        raise AuthenticationError("Erreur lors de la création de session")

def validate_session(session_token: str) -> Optional[Dict[str, Any]]:
    """
    Valide un token de session (via ORM).
    
    Args:
        session_token: Le token de session à valider
        
    Returns:
        Dict avec les informations de l'utilisateur si valide, None sinon
    """
    try:
        session = get_db_session()
        try:
            row = session.query(DbSession, User).join(
                User, DbSession.user_id == User.id
            ).filter(
                DbSession.session_token == session_token,
                DbSession.expires_at > datetime.now(),
                DbSession.invalidated == False,
                User.is_active == True
            ).first()
            
            if row:
                s, u = row
                logger.debug(f"Session valide pour l'utilisateur {u.username}")
                return {
                    "user_id": s.user_id,
                    "created_at": s.created_at,
                    "expires_at": s.expires_at,
                    "ip_address": s.ip_address,
                    "mfa_verified": s.mfa_verified,
                    "username": u.username,
                    "email": u.email,
                    "is_active": u.is_active,
                    "role": u.role,
                    "mfa_enabled": getattr(u, 'mfa_enabled', False)
                }
            else:
                logger.debug("Session invalide ou expirée")
                return None
        finally:
            session.close()
                
    except Exception as e:
        logger.error(f"Erreur lors de la validation de session: {e}")
        return None

def invalidate_session(session_token: str) -> bool:
    """
    Invalide une session (déconnexion) via ORM.
    
    Args:
        session_token: Le token de session à invalider
        
    Returns:
        True si la session a été invalidée avec succès
    """
    try:
        session = get_db_session()
        try:
            sess = session.query(DbSession).filter(DbSession.session_token == session_token).first()
            if sess:
                sess.invalidated = True
                session.commit()
                logger.info(f"Session invalidée: {session_token}")
                return True
            else:
                logger.warning("Tentative d'invalidation d'une session inexistante")
                return False
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
                
    except Exception as e:
        logger.error(f"Erreur lors de l'invalidation de session: {e}")
        return False

def cleanup_expired_sessions() -> None:
    """Nettoie les sessions expirées (via ORM)."""
    try:
        session = get_db_session()
        try:
            now = datetime.now()
            deleted_count = session.query(DbSession).filter(
                or_(DbSession.expires_at < now, DbSession.invalidated == True)
            ).delete()
            session.commit()
            
            if deleted_count > 0:
                logger.info(f"Nettoyé {deleted_count} sessions expirées")
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
                
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage des sessions: {e}")

def authenticate_user(
    username: str,
    password: str,
    ip_address: str = "unknown",
    totp_code: str = None,
    recovery_code: str = None,
    user_agent: str = "unknown"
) -> Dict[str, Any]:
    """
    Authentifie un utilisateur avec protection contre le brute force et alertes de sécurité.
    
    ASVS 6.3.1: Rate limiting multi-niveaux (IP, user+IP, username)
    ASVS 6.3.3, 6.5.1: MFA obligatoire si activé, vérifié avant émission de session
    ASVS 6.3.5: Notifications lors de tentatives suspectes (nouvel appareil/IP, échecs répétés,
                auth partielle avec mot de passe correct mais MFA échoué, reconnexion inactive)
    ASVS 6.3.8: Protection timing attack (hash factice pour utilisateur inexistant)
    
    Args:
        username: Nom d'utilisateur
        password: Mot de passe en clair
        ip_address: Adresse IP du client
        totp_code: Code TOTP (si MFA activé)
        recovery_code: Code de récupération (si MFA activé et TOTP non fourni)
        user_agent: Empreinte / user agent du client
        
    Returns:
        Dict avec 'success' (bool), 'session_token' (str si succès), 'mfa_required' (bool), 'errors' (list)
    """
    # Import ici pour éviter la dépendance circulaire
    from .auth_mfa import is_mfa_enabled, get_totp_secret, verify_totp_code, verify_recovery_code
    
    # Nettoyer les anciennes tentatives périodiquement
    cleanup_old_attempts()
    cleanup_expired_sessions()
    
    # Vérifier la limitation de taux
    rate_limit_result = check_rate_limit(username, ip_address)
    
    # Appliquer un délai progressif si nécessaire (6.3.1)
    if rate_limit_result['delay'] > 0:
        time.sleep(rate_limit_result['delay'])
    
    if not rate_limit_result['allowed']:
        record_login_attempt(username, ip_address, False)
        return {
            "success": False,
            "errors": [rate_limit_result['reason']],
            "locked_until": rate_limit_result.get('unlock_time')
        }
    
    # Récupérer l'utilisateur
    try:
        user = get_user_by_username(username)
    except Exception:
        # Keep database details out of the authentication response and logs.
        logger.error("Database error while looking up login account")
        return {
            "success": False,
            "errors": ["Nom d'utilisateur ou mot de passe incorrect"]
        }
    
    # ASVS 6.3.8: Protection timing attack
    # Si l'utilisateur n'existe pas, exécuter quand même une vérification Argon2
    # avec un hash factice pour avoir un temps de réponse comparable
    if not user:
        # Vérifier avec un hash factice pour garder le même timing
        try:
            ph.verify(_get_dummy_hash(), "dummy_password")
        except:
            pass
        record_login_attempt(username, ip_address, False)
        return {
            "success": False,
            "errors": [INVALID_CREDENTIALS_MESSAGE]
        }
    
    # Vérifier si l'utilisateur est actif
    if not user["is_active"]:
        # Vérifier avec hash factice pour timing constant
        try:
            ph.verify(_get_dummy_hash(), "dummy_password")
        except:
            pass
        record_login_attempt(username, ip_address, False)
        return {
            "success": False,
            "errors": [INVALID_CREDENTIALS_MESSAGE]  # Message générique
        }
    
    # Vérifier le mot de passe (timing réel)

    if not verify_password(password, user["password_hash"]):
        record_login_attempt(username, ip_address, False)
        return {
            "success": False,
            "errors": [INVALID_CREDENTIALS_MESSAGE]
        }

        
    
    # La MFA est obligatoire pour tous les comptes. Un compte sans facteur validé
    # reçoit uniquement une session limitée à l'enrôlement MFA.
    user_id = user["id"]
    enrollment_db = get_db_session()
    try:
        needs_mfa_enrollment = enrollment_db.query(MfaReenrollment).filter(
            MfaReenrollment.user_id == user_id).first() is not None
    finally:
        enrollment_db.close()
    mfa_enabled = is_mfa_enabled(user_id)
    if needs_mfa_enrollment or not mfa_enabled:
        restricted_token = create_session(user_id, ip_address, mfa_verified=False)
        record_login_attempt(username, ip_address, True)
        return {
            "success": True, "session_token": restricted_token, "mfa_enrollment_required": True,
            "user": {
                "id": user["id"], "username": user["username"], "email": user["email"],
                "role": user["role"], "mfa_enabled": False,
                "mfa_enrollment_required": True,
            }
        }
    mfa_required = True
    
    if mfa_required:
        # MFA est activé, vérifier le second facteur
        if not totp_code and not recovery_code:
            # Pas de second facteur fourni, demander le code
            # Ne pas créer de session, mais indiquer que le MFA est requis
            return {
                "success": False,
                "mfa_required": True,
                "errors": ["Second facteur requis (code TOTP ou code de récupération)"],
                "user_id_temp": user_id  # Pour la prochaine requête
            }
        
        # Vérifier le second facteur
        mfa_valid = False
        
        if totp_code:
            secret = get_totp_secret(user_id)
            if secret:
                mfa_valid = verify_totp_code(secret, totp_code, user_id)
            
        elif recovery_code:
            mfa_valid = verify_recovery_code(user_id, recovery_code)
        
        if not mfa_valid:
            record_login_attempt(username, ip_address, False)
            
            # ASVS 6.3.5: Alerte si mot de passe correct mais échec MFA (authentification partielle)
            try:
                notif_svc = get_notification_service()
                notif_svc.notify_partial_auth_failure(
                    recipient=user["email"],
                    username=user["username"],
                    ip_address=ip_address
                )
            except Exception as e:
                logger.error(f"Erreur notification échec MFA: {e}")

            return {
                "success": False,
                "errors": ["Code d'authentification invalide"]
            }
    
    # Authentification réussie (mot de passe + MFA si requis)
    try:
        # ASVS 6.3.5: Détection des cas de notification suspecte avant création de session
        try:
            notif_svc = get_notification_service()
            sess = get_db_session()
            try:
                # 1. Connexion réussie après plusieurs échecs consécutifs
                recent_failures = sess.query(func.count(LoginAttempt.id)).filter(
                    LoginAttempt.identifier == username,
                    LoginAttempt.identifier_type == 'username',
                    LoginAttempt.attempted_at > (datetime.now() - timedelta(minutes=15)),
                    LoginAttempt.success == False
                ).scalar() or 0
                
                if recent_failures >= SUSPICIOUS_FAILED_ATTEMPTS_THRESHOLD:
                    notif_svc.notify_login_after_failures(
                        recipient=user["email"],
                        username=user["username"],
                        ip_address=ip_address,
                        failed_count=recent_failures
                    )

                # 2. Reconnexion après longue inactivité
                db_user = sess.query(User).filter(User.id == user_id).first()
                if db_user:
                    if db_user.last_login_at and (datetime.now() - db_user.last_login_at) > LOGIN_INACTIVITY_THRESHOLD:
                        notif_svc.notify_inactive_login(
                            recipient=user["email"],
                            username=user["username"],
                            ip_address=ip_address,
                            last_login_date=db_user.last_login_at
                        )
                    db_user.last_login_at = datetime.now()

                # 3. Connexion depuis un nouvel appareil ou une nouvelle adresse IP
                known_dev = sess.query(UserDevice).filter(
                    UserDevice.user_id == user_id,
                    UserDevice.ip_address == ip_address
                ).first()
                if not known_dev:
                    new_dev = UserDevice(
                        user_id=user_id,
                        ip_address=ip_address,
                        user_agent=user_agent or "unknown",
                        first_seen=datetime.now(),
                        last_seen=datetime.now()
                    )
                    sess.add(new_dev)
                    notif_svc.notify_new_device(
                        recipient=user["email"],
                        username=user["username"],
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                else:
                    known_dev.last_seen = datetime.now()
                    if user_agent and user_agent != "unknown":
                        known_dev.user_agent = user_agent

                sess.commit()
            except Exception as e:
                sess.rollback()
                logger.error(f"Erreur détection alertes de connexion: {e}")
            finally:
                sess.close()
        except Exception as e:
            logger.error(f"Erreur globale notification de connexion réussie: {e}")

        session_token = create_session(user_id, ip_address, mfa_verified=mfa_required)
        record_login_attempt(username, ip_address, True)
        
        logger.info(f"Connexion réussie pour l'utilisateur: {username} (MFA: {mfa_required})")
        
        return {
            "success": True,
            "session_token": session_token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "mfa_enabled": True,
                "mfa_enrollment_required": False,
            }
        }
        
    except AuthenticationError as e:
        record_login_attempt(username, ip_address, False)
        return {
            "success": False,
            "errors": [str(e)]
        }

def logout_user(session_token: str) -> Dict[str, Any]:
    """
    Déconnecte un utilisateur en invalidant sa session.
    
    Args:
        session_token: Token de session à invalider
        
    Returns:
        Dict avec 'success' (bool) et 'message' (str)
    """
    success = invalidate_session(session_token)
    
    return {
        "success": success,
        "message": "Déconnexion réussie" if success else "Erreur lors de la déconnexion"
    }

def get_login_attempts_history(identifier: str, hours: int = 24) -> list:
    """
    Récupère l'historique des tentatives de connexion pour un identifiant.
    
    Args:
        identifier: Nom d'utilisateur ou adresse IP
        hours: Nombre d'heures d'historique à récupérer
        
    Returns:
        Liste des tentatives de connexion
    """
    try:
        session = get_db_session()
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            attempts = session.query(LoginAttempt).filter(
                LoginAttempt.identifier == identifier,
                LoginAttempt.attempted_at > cutoff_time
            ).order_by(LoginAttempt.attempted_at.desc()).all()
            
            return [
                {
                    "attempted_at": a.attempted_at,
                    "success": a.success,
                    "ip_address": a.ip_address
                }
                for a in attempts
            ]
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'historique: {e}")
        return []

# Fonctions utilitaires pour les tests
def test_authentication():
    """Fonction de test pour l'authentification."""
    print("=== Test d'authentification ===")
    
    # Test avec utilisateur inexistant
    result = authenticate_user("inexistant", "motdepasse")
    print(f"Utilisateur inexistant: {'✗ Échec attendu' if not result['success'] else '✓ Succès inattendu'}")
    
    print("\nPour tester complètement, créez d'abord un utilisateur avec auth_register.py")

if __name__ == "__main__":
    # Configuration du logging pour les tests
    logging.basicConfig(level=logging.INFO)
    
    # Test de base
    test_authentication()
