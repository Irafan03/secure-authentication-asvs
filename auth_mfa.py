"""
auth_mfa.py — Authentification multi-facteurs (MFA) par TOTP
ASVS 5.0.0 V6.5 - Niveau 2
"""

import logging
import secrets
import io
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from argon2 import PasswordHasher
import pyotp
import qrcode
from database import get_connection
from config import (
    TOTP_ISSUER, TOTP_INTERVAL, TOTP_DIGITS, TOTP_ALGORITHM,
    TOTP_SECRET_LENGTH, RECOVERY_CODES_COUNT, RECOVERY_CODE_LENGTH,
    RECOVERY_CODE_ENTROPY_BITS
)

logger = logging.getLogger(__name__)

# Hash pour les codes de récupération (< 112 bits d'entropie donc hachage requis - 6.5.2)
ph_recovery = PasswordHasher(
    time_cost=2,
    memory_cost=32768,
    parallelism=2,
    hash_len=32,
    salt_len=16
)


class MFAError(Exception):
    """Exception pour les erreurs MFA."""
    pass


def generate_totp_secret() -> str:
    """
    Génère un secret TOTP cryptographiquement sûr.
    
    ASVS 6.5.1, 6.5.4: Secret généré par un CSPRNG avec au moins 20 bits d'entropie.
    Utilise 256 bits (32 bytes) largement supérieur au minimum de 20 bits.
    
    Returns:
        Secret TOTP en base32
    """
    # Générer 32 bytes (256 bits) avec secrets (CSPRNG)
    random_bytes = secrets.token_bytes(TOTP_SECRET_LENGTH)
    # Encoder en base32 pour compatibilité TOTP
    secret = pyotp.random_base32(length=TOTP_SECRET_LENGTH)
    logger.info("Secret TOTP généré avec CSPRNG")
    return secret


def generate_totp_uri(username: str, secret: str) -> str:
    """
    Génère l'URI TOTP pour le QR code.
    
    Args:
        username: Nom d'utilisateur
        secret: Secret TOTP en base32
        
    Returns:
        URI otpauth:// pour le QR code
    """
    totp = pyotp.TOTP(
        secret,
        interval=TOTP_INTERVAL,
        digits=TOTP_DIGITS,
        issuer=TOTP_ISSUER
    )
    return totp.provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def generate_qr_code(uri: str) -> bytes:
    """
    Génère un QR code à partir d'un URI TOTP.
    
    Args:
        uri: URI otpauth://
        
    Returns:
        Image PNG du QR code en bytes
    """
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convertir en bytes
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()


def verify_totp_code(secret: str, code: str, user_id: int) -> bool:
    """
    Vérifie un code TOTP et empêche le rejeu.
    
    ASVS 6.5.3: Code TOTP utilisable une seule fois (rejeu refusé dans la même fenêtre).
    ASVS 6.5.5: Durée de validité de 30 secondes (TOTP_INTERVAL).
    
    Args:
        secret: Secret TOTP de l'utilisateur
        code: Code à vérifier
        user_id: ID de l'utilisateur (pour tracking du rejeu)
        
    Returns:
        True si le code est valide et non rejoué
    """
    totp = pyotp.TOTP(
        secret,
        interval=TOTP_INTERVAL,
        digits=TOTP_DIGITS
    )
    
    # Vérifier le code (permet une fenêtre de tolérance)
    is_valid = totp.verify(code, valid_window=1)
    
    if not is_valid:
        logger.warning(f"Code TOTP invalide pour l'utilisateur {user_id}")
        return False
    
    # Vérifier le rejeu : enregistrer le code utilisé
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Vérifier si ce code a déjà été utilisé récemment
            cursor.execute("""
                SELECT COUNT(*) FROM totp_used_codes
                WHERE user_id = %s AND code_hash = SHA2(%s, 256)
                AND used_at > DATE_SUB(NOW(), INTERVAL %s SECOND)
            """, (user_id, code, TOTP_INTERVAL * 2))  # 2x la fenêtre TOTP
            
            count = cursor.fetchone()[0]
            if count > 0:
                logger.warning(f"Tentative de rejeu de code TOTP pour l'utilisateur {user_id}")
                return False
            
            # Enregistrer le code comme utilisé
            cursor.execute("""
                INSERT INTO totp_used_codes (user_id, code_hash)
                VALUES (%s, SHA2(%s, 256))
            """, (user_id, code))
            
            conn.commit()
            logger.info(f"Code TOTP validé pour l'utilisateur {user_id}")
            return True
            
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du rejeu TOTP: {e}")
        # En cas d'erreur DB, refuser par sécurité
        return False


def generate_recovery_codes() -> List[Tuple[str, str]]:
    """
    Génère des codes de récupération à usage unique.
    
    ASVS 6.5.1, 6.5.2: Codes générés par CSPRNG, avec au moins 20 bits d'entropie,
    hachés avec un algorithme approuvé (Argon2) car < 112 bits.
    
    Returns:
        Liste de tuples (code_en_clair, code_haché)
    """
    codes = []
    
    for _ in range(RECOVERY_CODES_COUNT):
        # Générer un code avec CSPRNG
        # Format: XXXX-XXXX (8 caractères alphanumériques)
        code = secrets.token_urlsafe(RECOVERY_CODE_LENGTH)[:RECOVERY_CODE_LENGTH].upper()
        code = f"{code[:4]}-{code[4:]}"
        
        # Hacher le code (Argon2 car entropie < 112 bits)
        code_hash = ph_recovery.hash(code)
        
        codes.append((code, code_hash))
    
    logger.info(f"Générés {RECOVERY_CODES_COUNT} codes de récupération")
    return codes


def verify_recovery_code(user_id: int, code: str) -> bool:
    """
    Vérifie et consomme un code de récupération (usage unique).
    
    ASVS 6.5.2: Code utilisable une seule fois.
    
    Args:
        user_id: ID de l'utilisateur
        code: Code de récupération fourni
        
    Returns:
        True si le code est valide et non utilisé
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            
            # Récupérer les codes non utilisés
            cursor.execute("""
                SELECT id, code_hash FROM mfa_recovery_codes
                WHERE user_id = %s AND used = 0
            """, (user_id,))
            
            recovery_codes = cursor.fetchall()
            
            # Vérifier chaque code
            for rc in recovery_codes:
                try:
                    # Vérifier le hash Argon2
                    ph_recovery.verify(rc['code_hash'], code)
                    
                    # Code valide, le marquer comme utilisé
                    cursor.execute("""
                        UPDATE mfa_recovery_codes
                        SET used = 1, used_at = NOW()
                        WHERE id = %s
                    """, (rc['id'],))
                    
                    conn.commit()
                    logger.info(f"Code de récupération utilisé pour l'utilisateur {user_id}")
                    return True
                    
                except Exception:
                    # Code ne correspond pas, continuer
                    continue
            
            logger.warning(f"Code de récupération invalide pour l'utilisateur {user_id}")
            return False
            
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du code de récupération: {e}")
        return False


def enroll_mfa(user_id: int, username: str, *, session_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Enrôle un utilisateur dans le MFA TOTP.
    
    ASVS 6.5.1: Génère un secret TOTP et des codes de récupération.
    
    Args:
        user_id: ID de l'utilisateur
        username: Nom d'utilisateur
        
    Returns:
        Dict avec 'secret', 'qr_code_uri', 'recovery_codes'
    """
    from auth_login import require_valid_session
    require_valid_session(session_token, user_id)

    try:
        # Générer le secret TOTP
        secret = generate_totp_secret()
        
        # Générer l'URI et le QR code
        uri = generate_totp_uri(username, secret)
        
        # Générer les codes de récupération
        recovery_codes_data = generate_recovery_codes()
        recovery_codes_plain = [code[0] for code in recovery_codes_data]
        
        # Enregistrer dans la base (secret non haché mais codes de récupération hachés)
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Enregistrer le secret TOTP (pas encore validé)
            cursor.execute("""
                INSERT INTO mfa_secrets (user_id, totp_secret, validated)
                VALUES (%s, %s, 0)
                ON DUPLICATE KEY UPDATE totp_secret = %s, validated = 0
            """, (user_id, secret, secret))
            
            # Enregistrer les codes de récupération (hachés)
            cursor.execute("DELETE FROM mfa_recovery_codes WHERE user_id = %s", (user_id,))
            for _, code_hash in recovery_codes_data:
                cursor.execute("""
                    INSERT INTO mfa_recovery_codes (user_id, code_hash)
                    VALUES (%s, %s)
                """, (user_id, code_hash))
            
            conn.commit()
        
        logger.info(f"MFA enrôlé pour l'utilisateur {user_id}")
        
        return {
            "success": True,
            "secret": secret,
            "qr_code_uri": uri,
            "recovery_codes": recovery_codes_plain
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de l'enrôlement MFA: {e}")
        raise MFAError(f"Erreur lors de l'enrôlement MFA: {e}")


def validate_mfa_enrollment(user_id: int, code: str, *, session_token: Optional[str] = None) -> bool:
    """
    Valide l'enrôlement MFA en vérifiant le premier code TOTP.
    
    ASVS 6.5.1: L'enrôlement doit être validé par un premier code.
    
    Args:
        user_id: ID de l'utilisateur
        code: Premier code TOTP fourni
        
    Returns:
        True si la validation réussit
    """
    from auth_login import require_valid_session
    require_valid_session(session_token, user_id)

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            # Récupérer le secret non validé
            cursor.execute("""
                SELECT totp_secret FROM mfa_secrets
                WHERE user_id = %s AND validated = 0
            """, (user_id,))
            
            result = cursor.fetchone()
            if not result:
                logger.warning(f"Pas de secret MFA non validé pour l'utilisateur {user_id}")
                return False
            
            secret = result[0]
            
            # Vérifier le code (sans vérification de rejeu pour la validation initiale)
            totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL, digits=TOTP_DIGITS)
            is_valid = totp.verify(code, valid_window=1)
            
            if is_valid:
                # Marquer comme validé
                cursor.execute("""
                    UPDATE mfa_secrets
                    SET validated = 1, validated_at = NOW()
                    WHERE user_id = %s
                """, (user_id,))
                
                # Activer le MFA pour l'utilisateur
                cursor.execute("""
                    UPDATE users
                    SET mfa_enabled = 1
                    WHERE id = %s
                """, (user_id,))
                
                conn.commit()
                logger.info(f"MFA validé et activé pour l'utilisateur {user_id}")
                return True
            else:
                logger.warning(f"Code de validation MFA invalide pour l'utilisateur {user_id}")
                return False
                
    except Exception as e:
        logger.error(f"Erreur lors de la validation MFA: {e}")
        return False


def is_mfa_enabled(user_id: int) -> bool:
    """
    Vérifie si le MFA est activé pour un utilisateur.
    
    Args:
        user_id: ID de l'utilisateur
        
    Returns:
        True si le MFA est activé
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT mfa_enabled FROM users
                WHERE id = %s
            """, (user_id,))
            
            result = cursor.fetchone()
            return result[0] if result else False
            
    except Exception as e:
        logger.error(f"Erreur lors de la vérification MFA: {e}")
        return False


def get_totp_secret(user_id: int) -> Optional[str]:
    """
    Récupère le secret TOTP d'un utilisateur.
    
    Args:
        user_id: ID de l'utilisateur
        
    Returns:
        Secret TOTP ou None
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT totp_secret FROM mfa_secrets
                WHERE user_id = %s AND validated = 1
            """, (user_id,))
            
            result = cursor.fetchone()
            return result[0] if result else None
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du secret TOTP: {e}")
        return None


def cleanup_old_totp_codes() -> None:
    """Nettoie les anciens codes TOTP utilisés (> 5 minutes)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM totp_used_codes
                WHERE used_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)
            """)
            conn.commit()
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Nettoyé {deleted} codes TOTP anciens")
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage des codes TOTP: {e}")
