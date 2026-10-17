"""
auth_login.py — Authentification sécurisée avec protection contre le brute force
ASVS 5.0.0 — Niveau 2
"""

import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from auth_register import verify_password, get_user_by_username, ph
from database import get_connection
from config import (
    RATE_LIMIT_IP_MAX_ATTEMPTS, RATE_LIMIT_IP_WINDOW, RATE_LIMIT_IP_LOCKOUT,
    RATE_LIMIT_USER_IP_MAX_ATTEMPTS, RATE_LIMIT_USER_IP_WINDOW, RATE_LIMIT_USER_IP_LOCKOUT,
    RATE_LIMIT_USERNAME_MAX_ATTEMPTS, RATE_LIMIT_USERNAME_WINDOW,
    RATE_LIMIT_USERNAME_DELAY_ENABLED, RATE_LIMIT_USERNAME_DELAY_BASE,
    RATE_LIMIT_USERNAME_DELAY_MULTIPLIER,
    SESSION_DURATION, SESSION_TOKEN_LENGTH, LOGIN_ATTEMPTS_RETENTION,
    DUMMY_PASSWORD_HASH
)
import mysql.connector

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

def generate_session_token() -> str:
    """
    Génère un token de session cryptographiquement sûr.
    
    Returns:
        Token de session hexadécimal
    """
    return secrets.token_hex(SESSION_TOKEN_LENGTH)

def record_login_attempt(username: str, ip_address: str, success: bool) -> None:
    """
    Enregistre une tentative de connexion pour le rate limiting.
    
    ASVS 6.3.1: Enregistre séparément par IP, par (username, IP) et par username
    pour permettre des seuils différents.
    
    Args:
        username: Nom d'utilisateur (peut être vide si énumération)
        ip_address: Adresse IP du client
        success: True si la connexion a réussi
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Enregistrement par IP
            cursor.execute(
                "INSERT INTO login_attempts (identifier, success, ip_address, identifier_type) VALUES (%s, %s, %s, %s)",
                (ip_address, success, ip_address, 'ip')
            )
            
            # Enregistrement par (username, IP) si username fourni
            if username:
                user_ip_identifier = f"{username}:{ip_address}"
                cursor.execute(
                    "INSERT INTO login_attempts (identifier, success, ip_address, identifier_type) VALUES (%s, %s, %s, %s)",
                    (user_ip_identifier, success, ip_address, 'user_ip')
                )
                
                # Enregistrement par username seul
                cursor.execute(
                    "INSERT INTO login_attempts (identifier, success, ip_address, identifier_type) VALUES (%s, %s, %s, %s)",
                    (username, success, ip_address, 'username')
                )
            
            conn.commit()
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement de la tentative de connexion: {e}")

def check_rate_limit(username: str, ip_address: str) -> Dict[str, Any]:
    """
    Vérifie le rate limiting selon ASVS 6.3.1.
    
    Trois niveaux de protection:
    1. Par IP: empêche les attaques distribuées depuis une même IP
    2. Par (username, IP): protège contre les attaques ciblées
    3. Par username: seuil très élevé avec ralentissement progressif (évite DoS sur compte)
    
    Args:
        username: Nom d'utilisateur
        ip_address: Adresse IP du client
        
    Returns:
        Dict avec:
        - 'allowed': True si la connexion est autorisée
        - 'reason': Raison du blocage si 'allowed' est False
        - 'delay': Délai à appliquer avant traitement (secondes)
        - 'unlock_time': Heure de déblocage si bloqué
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            current_time = datetime.now()
            
            # 1. Vérifier rate limit par IP
            ip_cutoff = current_time - RATE_LIMIT_IP_WINDOW
            cursor.execute("""
                SELECT COUNT(*) as failed_count, MAX(attempted_at) as last_attempt
                FROM login_attempts 
                WHERE identifier = %s 
                  AND identifier_type = 'ip'
                  AND attempted_at > %s 
                  AND success = 0
            """, (ip_address, ip_cutoff))
            
            result = cursor.fetchone()
            ip_failed_attempts = result[0] if result else 0
            ip_last_attempt = result[1] if result and result[1] else None
            
            if ip_failed_attempts >= RATE_LIMIT_IP_MAX_ATTEMPTS and ip_last_attempt:
                unlock_time = ip_last_attempt + RATE_LIMIT_IP_LOCKOUT
                if current_time < unlock_time:
                    return {
                        'allowed': False,
                        'reason': f"Trop de tentatives depuis cette adresse IP. Réessayez après {unlock_time.strftime('%H:%M:%S')}",
                        'unlock_time': unlock_time,
                        'delay': 0
                    }
            
            # 2. Vérifier rate limit par (username, IP)
            user_ip_identifier = f"{username}:{ip_address}"
            user_ip_cutoff = current_time - RATE_LIMIT_USER_IP_WINDOW
            cursor.execute("""
                SELECT COUNT(*) as failed_count, MAX(attempted_at) as last_attempt
                FROM login_attempts 
                WHERE identifier = %s 
                  AND identifier_type = 'user_ip'
                  AND attempted_at > %s 
                  AND success = 0
            """, (user_ip_identifier, user_ip_cutoff))
            
            result = cursor.fetchone()
            user_ip_failed_attempts = result[0] if result else 0
            user_ip_last_attempt = result[1] if result and result[1] else None
            
            if user_ip_failed_attempts >= RATE_LIMIT_USER_IP_MAX_ATTEMPTS and user_ip_last_attempt:
                unlock_time = user_ip_last_attempt + RATE_LIMIT_USER_IP_LOCKOUT
                if current_time < unlock_time:
                    return {
                        'allowed': False,
                        'reason': f"Trop de tentatives échouées. Réessayez après {unlock_time.strftime('%H:%M:%S')}",
                        'unlock_time': unlock_time,
                        'delay': 0
                    }
            
            # 3. Vérifier rate limit par username (seuil élevé + délai progressif)
            username_cutoff = current_time - RATE_LIMIT_USERNAME_WINDOW
            cursor.execute("""
                SELECT COUNT(*) as failed_count
                FROM login_attempts 
                WHERE identifier = %s 
                  AND identifier_type = 'username'
                  AND attempted_at > %s 
                  AND success = 0
            """, (username, username_cutoff))
            
            result = cursor.fetchone()
            username_failed_attempts = result[0] if result else 0
            
            # Calculer le délai progressif si activé
            delay = 0
            if RATE_LIMIT_USERNAME_DELAY_ENABLED and username_failed_attempts > 0:
                # Délai exponentiel: base * (multiplier ^ failed_attempts)
                delay = RATE_LIMIT_USERNAME_DELAY_BASE * (RATE_LIMIT_USERNAME_DELAY_MULTIPLIER ** username_failed_attempts)
                # Limiter le délai max à 30 secondes
                delay = min(delay, 30.0)
            
            # Seuil très élevé pour éviter le DoS sur compte légitime
            if username_failed_attempts >= RATE_LIMIT_USERNAME_MAX_ATTEMPTS:
                return {
                    'allowed': False,
                    'reason': "Trop de tentatives de connexion pour ce compte. Veuillez réessayer plus tard",
                    'unlock_time': current_time + timedelta(hours=1),
                    'delay': 0
                }
            
            return {
                'allowed': True,
                'reason': None,
                'unlock_time': None,
                'delay': delay
            }
            
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du rate limit: {e}")
        # En cas d'erreur, autoriser mais logger
        return {'allowed': True, 'reason': None, 'unlock_time': None, 'delay': 0}

def cleanup_old_attempts() -> None:
    """Nettoie les anciennes tentatives de connexion."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff_time = datetime.now() - LOGIN_ATTEMPTS_RETENTION
            
            cursor.execute(
                "DELETE FROM login_attempts WHERE attempted_at < %s",
                (cutoff_time,)
            )
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                logger.info(f"Nettoyé {deleted_count} anciennes tentatives de connexion")
                
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage des tentatives: {e}")

def create_session(user_id: int, ip_address: str = None, mfa_verified: bool = False) -> str:
    """
    Crée une nouvelle session pour un utilisateur.
    
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
        
        with get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO sessions (session_token, user_id, expires_at, ip_address, mfa_verified)
                VALUES (%s, %s, %s, %s, %s)
            """, (session_token, user_id, expires_at, ip_address, mfa_verified))
            
            conn.commit()
            
        logger.info(f"Session créée pour l'utilisateur ID {user_id} (MFA: {mfa_verified})")
        return session_token
        
    except Exception as e:
        logger.error(f"Erreur lors de la création de session pour l'utilisateur {user_id}: {e}")
        raise AuthenticationError("Erreur lors de la création de session")

def validate_session(session_token: str) -> Optional[Dict[str, Any]]:
    """
    Valide un token de session.
    
    Args:
        session_token: Le token de session à valider
        
    Returns:
        Dict avec les informations de l'utilisateur si valide, None sinon
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT s.user_id, s.created_at, s.expires_at, s.ip_address, s.mfa_verified,
                       u.username, u.email, u.is_active, u.role, u.mfa_enabled
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token = %s 
                  AND s.expires_at > NOW()
                  AND s.invalidated = 0
                  AND u.is_active = 1
            """, (session_token,))
            
            session_data = cursor.fetchone()
            
            if session_data:
                logger.debug(f"Session valide pour l'utilisateur {session_data['username']}")
                return session_data
            else:
                logger.debug(f"Session invalide ou expirée: {session_token}")
                return None
                
    except Exception as e:
        logger.error(f"Erreur lors de la validation de session: {e}")
        return None

def invalidate_session(session_token: str) -> bool:
    """
    Invalide une session (déconnexion).
    
    Args:
        session_token: Le token de session à invalider
        
    Returns:
        True si la session a été invalidée avec succès
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE sessions 
                SET invalidated = 1 
                WHERE session_token = %s
            """, (session_token,))
            
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"Session invalidée: {session_token}")
                return True
            else:
                logger.warning(f"Tentative d'invalidation d'une session inexistante: {session_token}")
                return False
                
    except Exception as e:
        logger.error(f"Erreur lors de l'invalidation de session: {e}")
        return False

def cleanup_expired_sessions() -> None:
    """Nettoie les sessions expirées."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM sessions 
                WHERE expires_at < NOW() OR invalidated = 1
            """)
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                logger.info(f"Nettoyé {deleted_count} sessions expirées")
                
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage des sessions: {e}")

def authenticate_user(username: str, password: str, ip_address: str = "unknown", totp_code: str = None, recovery_code: str = None) -> Dict[str, Any]:
    """
    Authentifie un utilisateur avec protection contre le brute force.
    
    ASVS 6.3.1: Rate limiting multi-niveaux (IP, user+IP, username)
    ASVS 6.3.3, 6.5.1: MFA obligatoire si activé, vérifié avant émission de session
    ASVS 6.3.8: Protection timing attack (hash factice pour utilisateur inexistant)
    
    Args:
        username: Nom d'utilisateur
        password: Mot de passe en clair
        ip_address: Adresse IP du client
        totp_code: Code TOTP (si MFA activé)
        recovery_code: Code de récupération (si MFA activé et TOTP non fourni)
        
    Returns:
        Dict avec 'success' (bool), 'session_token' (str si succès), 'mfa_required' (bool), 'errors' (list)
    """
    # Import ici pour éviter la dépendance circulaire
    from auth_mfa import is_mfa_enabled, get_totp_secret, verify_totp_code, verify_recovery_code
    
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
    user = get_user_by_username(username)
    
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
            "errors": ["Nom d'utilisateur ou mot de passe incorrect"]
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
            "errors": ["Nom d'utilisateur ou mot de passe incorrect"]  # Message générique
        }
    
    # Vérifier le mot de passe (timing réel)
    if not verify_password(password, user["password_hash"]):
        record_login_attempt(username, ip_address, False)
        return {
            "success": False,
            "errors": ["Nom d'utilisateur ou mot de passe incorrect"]
        }
    
    # Mot de passe correct, vérifier si MFA est requis
    user_id = user["id"]
    mfa_required = is_mfa_enabled(user_id)
    
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
            # Vérifier le code TOTP
            secret = get_totp_secret(user_id)
            if secret:
                mfa_valid = verify_totp_code(secret, totp_code, user_id)
            
        elif recovery_code:
            # Vérifier le code de récupération
            mfa_valid = verify_recovery_code(user_id, recovery_code)
        
        if not mfa_valid:
            record_login_attempt(username, ip_address, False)
            return {
                "success": False,
                "errors": ["Code d'authentification invalide"]
            }
    
    # Authentification réussie (mot de passe + MFA si requis)
    try:
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
                "role": user["role"]
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
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            cursor.execute("""
                SELECT attempted_at, success, ip_address
                FROM login_attempts
                WHERE identifier = %s AND attempted_at > %s
                ORDER BY attempted_at DESC
            """, (identifier, cutoff_time))
            
            return cursor.fetchall()
            
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