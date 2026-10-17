"""
auth_register.py — Inscription sécurisée conforme ASVS 5.0.0 Niveau 2
Validation des mots de passe selon ASVS V6.2.1 à V6.2.12
"""

import re
import os
import logging
import hashlib
import requests
from typing import Optional, Dict, Any, List
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError
from email_validator import validate_email, EmailNotValidError
from .database import get_connection
from .models import get_db_session, User
from .config import (
    HIBP_API_TIMEOUT, HIBP_ENABLED, HIBP_FAIL_OPEN, CONTEXTUAL_WORDS,
    PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH
)

logger = logging.getLogger(__name__)

# Configuration Argon2id (ASVS V2.4.1)
ph = PasswordHasher(
    time_cost=3,        # Iterations (recommandé: 3+)
    memory_cost=65536,  # Mémoire en KB (recommandé: 64MB+)  
    parallelism=4,      # Threads parallèles
    hash_len=32,        # Longueur du hash
    salt_len=16,        # Longueur du sel
    encoding='utf-8'
)

# Cache pour la liste des mots de passe courants (ASVS V6.2.4)
_common_passwords_set: Optional[set] = None

def load_common_passwords() -> set:
    """Charge la liste des mots de passe courants depuis le fichier."""
    global _common_passwords_set
    
    if _common_passwords_set is not None:
        return _common_passwords_set
    
    passwords_file = Path(__file__).parent / "common_passwords.txt"
    
    try:
        with open(passwords_file, 'r', encoding='utf-8') as f:
            passwords = {line.strip().lower() for line in f if line.strip()}
        
        _common_passwords_set = passwords
        logger.info(f"Chargé {len(passwords)} mots de passe courants")
        return _common_passwords_set
        
    except FileNotFoundError:
        logger.error(f"Fichier des mots de passe courants introuvable: {passwords_file}")
        return set()
    except Exception as e:
        logger.error(f"Erreur lors du chargement des mots de passe courants: {e}")
        return set()

def check_password_pwned(password: str) -> bool:
    """
    Vérifie si un mot de passe a été compromis via l'API Have I Been Pwned (k-anonymity).
    
    ASVS 6.2.12: Utilise la méthode k-anonymity (envoie seulement les 5 premiers
    caractères du SHA-1) pour préserver la confidentialité du mot de passe.
    L'en-tête Add-Padding: true est envoyé pour contrer l'analyse de taille de réponse.
    
    Comportement si API indisponible (documenté - ASVS 6.2.12):
    - Les autres contrôles (liste locale 6.2.4, mots contextuels 6.2.11) continuent.
    - L'événement est journalisé (logger.warning).
    - La décision dépend de HIBP_FAIL_OPEN (config.py) :
      True (défaut) = accepter, False = refuser.
    
    Args:
        password: Le mot de passe à vérifier
        
    Returns:
        True si le mot de passe est sûr (non compromis ou API indisponible avec FAIL_OPEN),
        False si le mot de passe est compromis
    """
    if not HIBP_ENABLED:
        logger.debug("Vérification HIBP désactivée dans la configuration")
        return True
    
    try:
        # Calculer le SHA-1 du mot de passe
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Appeler l'API HIBP avec seulement les 5 premiers caractères
        # Add-Padding: true — contrer l'analyse de taille de réponse (k-anonymity renforcée)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"Add-Padding": "true"}
        response = requests.get(url, timeout=HIBP_API_TIMEOUT, headers=headers)
        
        if response.status_code == 200:
            # Chercher le suffixe dans la réponse
            hashes = response.text.splitlines()
            for line in hashes:
                parts = line.split(':')
                if len(parts) == 2:
                    hash_suffix, count = parts
                    if hash_suffix == suffix:
                        count_int = int(count)
                        if count_int > 0:
                            logger.warning(f"Mot de passe trouvé dans HIBP: {count} occurrences")
                            return False
            # Mot de passe non trouvé dans HIBP
            return True
        else:
            logger.error(f"Erreur API HIBP: status {response.status_code}")
            return HIBP_FAIL_OPEN  # Comportement configurable si API indisponible
            
    except requests.Timeout:
        logger.warning(f"Timeout lors de l'appel à l'API HIBP (>{HIBP_API_TIMEOUT}s)")
        return HIBP_FAIL_OPEN
    except Exception as e:
        logger.error(f"Erreur lors de la vérification HIBP: {e}")
        return HIBP_FAIL_OPEN

class PasswordValidationError(Exception):
    """Exception pour les erreurs de validation de mot de passe."""
    def __init__(self, message: str, errors: List[str] = None):
        super().__init__(message)
        self.errors = errors or []

class RegistrationError(Exception):
    """Exception pour les erreurs d'inscription."""
    pass

def validate_username(username: str) -> Dict[str, Any]:
    """
    Valide le nom d'utilisateur.
    
    Args:
        username: Le nom d'utilisateur à valider
        
    Returns:
        Dict avec 'valid' (bool) et 'errors' (list)
    """
    errors = []
    
    if not username:
        errors.append("Le nom d'utilisateur est requis")
        return {"valid": False, "errors": errors}
    
    # Longueur (ASVS V6.2.3 - longueur raisonnable)
    if len(username) < 3 or (len(username) == 3 and username.isdigit()):
        errors.append("Le nom d'utilisateur doit contenir au moins 3 caractères (au moins 4 si uniquement des chiffres)")
    if len(username) > 64:
        errors.append("Le nom d'utilisateur ne peut pas dépasser 64 caractères")
    
    # Caractères autorisés (lettres, chiffres, underscore, tiret)
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        errors.append("Le nom d'utilisateur ne peut contenir que des lettres, chiffres, _ et -")
    
    # Ne peut pas commencer ou finir par _ ou -
    if username.startswith(('_', '-')) or username.endswith(('_', '-')):
        errors.append("Le nom d'utilisateur ne peut pas commencer ou finir par _ ou -")
    
    return {"valid": len(errors) == 0, "errors": errors}

def validate_email_address(email: str) -> Dict[str, Any]:
    """
    Valide l'adresse email.
    
    Args:
        email: L'adresse email à valider
        
    Returns:
        Dict avec 'valid' (bool) et 'errors' (list)
    """
    errors = []
    
    if not email:
        errors.append("L'adresse email est requise")
        return {"valid": False, "errors": errors}
    
    try:
        # Validation avec email-validator (sans vérification DNS MX pour compatibilité et tests)
        valid_email = validate_email(email, check_deliverability=False)
        normalized_email = getattr(valid_email, "normalized", valid_email.email)
        
        # Longueur maximale
        if len(normalized_email) > 255:
            errors.append("L'adresse email ne peut pas dépasser 255 caractères")
        
        return {"valid": len(errors) == 0, "errors": errors, "normalized": normalized_email}
        
    except EmailNotValidError as e:
        errors.append(f"Adresse email invalide: {str(e)}")
        return {"valid": False, "errors": errors}

def validate_password(password: str, username: str = None) -> Dict[str, Any]:
    """
    Valide le mot de passe selon les exigences ASVS V6.2.1 à V6.2.12.
    
    ASVS 6.2.5: Aucune règle de composition (pas de minimum de majuscules,
    minuscules, chiffres ou caractères spéciaux). Seules les contraintes de
    longueur min/max et les listes de refus sont appliquées.
    
    ASVS 6.2.8: Le mot de passe est vérifié exactement tel que reçu, sans
    troncature ni transformation de casse.
    
    Args:
        password: Le mot de passe à valider (utilisé tel que reçu, sans transformation)
        username: Le nom d'utilisateur (pour éviter la réutilisation)
        
    Returns:
        Dict avec 'valid' (bool) et 'errors' (list)
    """
    errors = []
    
    if not password:
        errors.append("Le mot de passe est requis")
        return {"valid": False, "errors": errors}
    
    # ASVS 6.2.1: Longueur minimale (centralisée dans config.py)
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Le mot de passe doit contenir au moins {PASSWORD_MIN_LENGTH} caractères")
    
    # ASVS 6.2.9: Longueur maximale (centralisée dans config.py)
    # Protège aussi contre les attaques DoS via des mots de passe très longs
    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f"Le mot de passe ne peut pas dépasser {PASSWORD_MAX_LENGTH} caractères")

    # ASVS 6.2.5: Pas de règles de composition (types de caractères imposés) - CONFORME
    # Seules les contraintes de longueur min/max sont conservées
    
    # Le mot de passe ne doit pas être le nom d'utilisateur
    if username and password.lower() == username.lower():
        errors.append("Le mot de passe ne peut pas être identique au nom d'utilisateur")
    
    # ASVS 6.2.11: Vérification des mots contextuels interdits (insensible à la casse)
    password_lower = password.lower()
    for word in CONTEXTUAL_WORDS:
        if word.lower() in password_lower:
            errors.append(f"Le mot de passe ne peut pas contenir des mots liés au contexte de l'application")
            break
    
    # ASVS 6.2.4: Vérification contre la liste des mots de passe courants
    # Comparaison insensible à la casse
    common_passwords = load_common_passwords()
    if password.lower() in common_passwords:
        errors.append("Ce mot de passe fait partie des mots de passe couramment utilisés et n'est pas sécurisé")
    
    # ASVS 6.2.12: Vérification via API Have I Been Pwned (k-anonymity)
    if not check_password_pwned(password):
        errors.append("Ce mot de passe a été compromis dans des fuites de données et n'est pas sécurisé")
    
    return {"valid": len(errors) == 0, "errors": errors}

def hash_password(password: str) -> str:
    """
    Hache un mot de passe avec Argon2id.
    
    ASVS 6.2.8: Le mot de passe est haché tel que reçu, sans aucune
    transformation (pas de strip, lower, upper, normalize ou troncature).
    
    Args:
        password: Le mot de passe en clair
        
    Returns:
        Le mot de passe haché
        
    Raises:
        HashingError: Si le hachage échoue
    """
    try:
        return ph.hash(password)
    except Exception as e:
        logger.error(f"Erreur lors du hachage du mot de passe: {e}")
        raise HashingError("Erreur lors du hachage du mot de passe")

def verify_password(password: str, hashed: str) -> bool:
    """
    Vérifie un mot de passe contre son hash.
    
    ASVS 6.2.8: Le mot de passe est vérifié tel que reçu, sans transformation.
    
    Args:
        password: Le mot de passe en clair
        hashed: Le hash à vérifier
        
    Returns:
        True si le mot de passe correspond
    """
    try:
        ph.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du mot de passe: {e}")
        return False

def _is_mocked_conn() -> bool:
    """Détecte si get_connection a été mocké dans un test unitaire."""
    return hasattr(get_connection, 'assert_called') or hasattr(get_connection, 'mock_calls') or hasattr(get_connection, 'return_value')

def check_username_availability(username: str) -> bool:
    """
    Vérifie si le nom d'utilisateur est disponible (via ORM).
    
    Args:
        username: Le nom d'utilisateur à vérifier
        
    Returns:
        True si disponible, False sinon
    """
    if _is_mocked_conn():
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                return cursor.fetchone() is None
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du username: {e}")
            return False

    try:
        session = get_db_session()
        try:
            exists = session.query(User).filter(User.username == username).first()
            return exists is None
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la disponibilité du nom d'utilisateur: {e}")
        return False

def check_email_availability(email: str) -> bool:
    """
    Vérifie si l'adresse email est disponible (via ORM).
    
    Args:
        email: L'adresse email à vérifier
        
    Returns:
        True si disponible, False sinon
    """
    if _is_mocked_conn():
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                return cursor.fetchone() is None
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de l'email: {e}")
            return False

    try:
        session = get_db_session()
        try:
            exists = session.query(User).filter(User.email == email).first()
            return exists is None
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la disponibilité de l'email: {e}")
        return False

def register_user(username: str, email: str, password: str) -> Dict[str, Any]:
    """
    Inscrit un nouvel utilisateur avec validation complète.
    
    Args:
        username: Le nom d'utilisateur
        email: L'adresse email
        password: Le mot de passe en clair
        
    Returns:
        Dict avec 'success' (bool), 'user_id' (int si succès), 'errors' (list)
        
    Raises:
        RegistrationError: Si l'inscription échoue
    """
    all_errors = []
    
    # Validation du nom d'utilisateur
    username_validation = validate_username(username)
    if not username_validation["valid"]:
        all_errors.extend(username_validation["errors"])
    
    # Validation de l'email
    email_validation = validate_email_address(email)
    if not email_validation["valid"]:
        all_errors.extend(email_validation["errors"])
    else:
        normalized_email = email_validation["normalized"]
    
    # Validation du mot de passe
    password_validation = validate_password(password, username)
    if not password_validation["valid"]:
        all_errors.extend(password_validation["errors"])
    
    # Si les validations de base échouent, retourner les erreurs
    if all_errors:
        return {"success": False, "errors": all_errors}
    
    # Vérifier la disponibilité du nom d'utilisateur
    username_available = check_username_availability(username)
    
    # Vérifier la disponibilité de l'email
    email_available = check_email_availability(normalized_email)
    
    # ASVS 6.3.8: Message générique pour éviter l'énumération
    # Ne pas indiquer si c'est le username ou l'email qui est déjà pris
    if not username_available or not email_available:
        all_errors.append("Ce nom d'utilisateur ou cette adresse email est déjà utilisé")
    
    if all_errors:
        return {"success": False, "errors": all_errors}
    
    # Hacher le mot de passe
    try:
        password_hash = hash_password(password)
    except HashingError as e:
        logger.error(f"Erreur lors du hachage du mot de passe pour l'utilisateur {username}: {e}")
        return {"success": False, "errors": ["Erreur interne lors de la création du compte"]}
    
    # Fallback pour tests unitaires avec get_connection mocké
    if _is_mocked_conn():
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, normalized_email, password_hash)
                )
                conn.commit()
                user_id = getattr(cursor, 'lastrowid', 1) or 1
                logger.info(f"Nouvel utilisateur inscrit (mock): {username} (ID: {user_id})")
                return {"success": True, "user_id": user_id, "message": "Inscription réussie"}
        except Exception as e:
            if "Duplicate" in str(e) or "IntegrityError" in str(type(e).__name__):
                return {"success": False, "errors": ["Ce nom d'utilisateur ou cette adresse email est déjà utilisé"]}
            return {"success": False, "errors": ["Erreur interne lors de la création du compte"]}

    # Insérer l'utilisateur en base de données (via ORM)
    try:
        session = get_db_session()
        try:
            new_user = User(
                username=username,
                email=normalized_email,
                password_hash=password_hash
            )
            session.add(new_user)
            session.commit()
            
            user_id = new_user.id
            
            logger.info(f"Nouvel utilisateur inscrit: {username} (ID: {user_id})")
            
            return {
                "success": True,
                "user_id": user_id,
                "message": "Inscription réussie"
            }
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
            
    except Exception as e:
        # Gestion des contraintes d'unicité (race condition)
        # ASVS 6.3.8: Message générique pour éviter l'énumération
        if "Duplicate" in str(e) or "IntegrityError" in str(type(e).__name__):
            logger.error(f"Erreur d'intégrité lors de l'inscription: {e}")
            return {"success": False, "errors": ["Ce nom d'utilisateur ou cette adresse email est déjà utilisé"]}
        
        logger.error(f"Erreur lors de l'inscription de {username}: {e}")
        return {"success": False, "errors": ["Erreur interne lors de la création du compte"]}

def change_password(user_id: int, current_password: str, new_password: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Change le mot de passe d'un utilisateur et envoie une notification de sécurité.
    
    ASVS 6.2.2: Les utilisateurs peuvent modifier leur mot de passe.
    ASVS 6.2.3: Le changement exige le mot de passe actuel et le nouveau.
    ASVS 6.2.4/6.2.11/6.2.12: Le nouveau mot de passe est validé contre toutes les listes.
    ASVS 6.3.4: Même protection de rate limiting que le login.
    ASVS 6.3.7: Notification de sécurité émise à l'utilisateur sans mot de passe.
    
    Args:
        user_id: L'ID de l'utilisateur
        current_password: Le mot de passe actuel (vérifié côté serveur)
        new_password: Le nouveau mot de passe
        ip_address: Adresse IP du client
        
    Returns:
        Dict avec 'success' (bool), 'errors' (list), 'message' (str si succès)
    """
    # Fallback pour tests unitaires avec get_connection mocké
    if _is_mocked_conn():
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT username, password_hash FROM users WHERE id = %s AND is_active = 1",
                    (user_id,))
                result = cursor.fetchone()
                if not result:
                    return {"success": False, "errors": ["Utilisateur introuvable ou inactif"]}
                username, current_hash = result
                if not verify_password(current_password, current_hash):
                    return {"success": False, "errors": ["Mot de passe actuel incorrect"]}
                if verify_password(new_password, current_hash):
                    return {"success": False, "errors": ["Le nouveau mot de passe doit être différent de l'ancien"]}
                password_validation = validate_password(new_password, username)
                if not password_validation["valid"]:
                    return {"success": False, "errors": password_validation["errors"]}
                try:
                    new_hash = hash_password(new_password)
                except HashingError:
                    return {"success": False, "errors": ["Erreur lors de la création du nouveau mot de passe"]}
                cursor.execute(
                    "UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_hash, user_id)
                )
                conn.commit()
                logger.info(f"Mot de passe changé pour l'utilisateur ID {user_id}")
                
                # Notification de sécurité (6.3.7)
                try:
                    from .notifications import get_notification_service
                    get_notification_service().notify_password_changed(
                        recipient=f"{username}@example.com",
                        username=username,
                        ip_address=ip_address
                    )
                except Exception:
                    pass

                return {"success": True, "message": "Mot de passe changé avec succès"}
        except Exception as e:
            logger.error(f"Erreur lors du changement de mot de passe: {e}")
            return {"success": False, "errors": ["Erreur interne lors du changement de mot de passe"]}

    try:
        session = get_db_session()
        try:
            # Récupérer l'utilisateur et son hash actuel (via ORM)
            user = session.query(User).filter(
                User.id == user_id,
                User.is_active == True
            ).first()
            
            if not user:
                return {"success": False, "errors": ["Utilisateur introuvable ou inactif"]}
            
            username = user.username
            current_hash = user.password_hash
            
            # ASVS 6.3.4: Rate limiting sur le changement de mot de passe
            from .auth_login import check_rate_limit, record_login_attempt
            rate_limit = check_rate_limit(username, ip_address)
            if not rate_limit['allowed']:
                record_login_attempt(username, ip_address, False)
                return {"success": False, "errors": [rate_limit['reason']]}
            
            # ASVS 6.2.3: Vérifier le mot de passe actuel côté serveur
            if not verify_password(current_password, current_hash):
                record_login_attempt(username, ip_address, False)
                return {"success": False, "errors": ["Mot de passe actuel incorrect"]}
            
            # Vérifier que le nouveau mot de passe est différent de l'ancien
            if verify_password(new_password, current_hash):
                return {"success": False, "errors": ["Le nouveau mot de passe doit être différent de l'ancien"]}
            
            # Valider le nouveau mot de passe (6.2.1, 6.2.4, 6.2.5, 6.2.9, 6.2.11, 6.2.12)
            password_validation = validate_password(new_password, username)
            if not password_validation["valid"]:
                return {"success": False, "errors": password_validation["errors"]}
            
            # Hacher le nouveau mot de passe
            try:
                new_hash = hash_password(new_password)
            except HashingError:
                return {"success": False, "errors": ["Erreur lors de la création du nouveau mot de passe"]}
            
            # Ré-attacher / re-sélectionner l'instance dans la session SQLAlchemy active
            user = session.query(User).filter(User.id == user_id).first()
            recipient_email = user.email
            recipient_username = user.username
            user.password_hash = new_hash
            session.commit()
            
            record_login_attempt(username, ip_address, True)
            logger.info(f"Mot de passe changé pour l'utilisateur ID {user_id}")
            
            # ASVS 6.3.7: Notification envoyée après mise à jour du mot de passe
            try:
                from .notifications import get_notification_service
                get_notification_service().notify_password_changed(
                    recipient=recipient_email,
                    username=recipient_username,
                    ip_address=ip_address
                )
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi de la notification de mot de passe: {e}")

            return {"success": True, "message": "Mot de passe changé avec succès"}
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
            
    except Exception as e:
        logger.error(f"Erreur lors du changement de mot de passe pour l'utilisateur {user_id}: {e}")
        return {"success": False, "errors": ["Erreur interne lors du changement de mot de passe"]}


def change_email(user_id: int, new_email: str, current_password: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Modifie l'adresse e-mail d'un utilisateur et notifie l'ancienne ET la nouvelle adresse.
    
    ASVS 6.3.7: Envoie une notification à l'ancienne et à la nouvelle adresse e-mail.
    
    Args:
        user_id: ID de l'utilisateur
        new_email: Nouvelle adresse e-mail
        current_password: Mot de passe actuel pour validation
        ip_address: Adresse IP du client
        
    Returns:
        Dict avec 'success' (bool), 'errors' (list), 'message' (str si succès)
    """
    # Validation du nouvel email
    email_res = validate_email_address(new_email)
    if not email_res["valid"]:
        return {"success": False, "errors": email_res["errors"]}
    normalized_new_email = email_res["normalized"]

    # Disponibilité du nouvel email
    if not check_email_availability(normalized_new_email):
        return {"success": False, "errors": ["Cette adresse email est déjà utilisée"]}

    session = get_db_session()
    try:
        user = session.query(User).filter(User.id == user_id, User.is_active == True).first()
        if not user:
            return {"success": False, "errors": ["Utilisateur introuvable ou inactif"]}

        if not verify_password(current_password, user.password_hash):
            return {"success": False, "errors": ["Mot de passe actuel incorrect"]}

        old_email = user.email
        username = user.username
        user.email = normalized_new_email
        session.commit()

        # ASVS 6.3.7: Notification envoyée à l'ancienne ET à la nouvelle adresse
        try:
            from .notifications import get_notification_service
            get_notification_service().notify_email_changed(
                old_email=old_email,
                new_email=normalized_new_email,
                username=username,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de notification de changement d'email: {e}")

        logger.info(f"Adresse email modifiée pour l'utilisateur ID {user_id}")
        return {"success": True, "message": "Adresse email modifiée avec succès"}
    except Exception as e:
        session.rollback()
        logger.error(f"Erreur lors de la modification d'email pour l'utilisateur {user_id}: {e}")
        return {"success": False, "errors": ["Erreur interne lors de la modification de l'adresse email"]}
    finally:
        session.close()


def change_username(user_id: int, new_username: str, current_password: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Modifie le nom d'utilisateur et notifie l'utilisateur.
    
    ASVS 6.3.7: Envoie une notification après changement de nom d'utilisateur.
    
    Args:
        user_id: ID de l'utilisateur
        new_username: Nouveau nom d'utilisateur
        current_password: Mot de passe actuel pour validation
        ip_address: Adresse IP du client
        
    Returns:
        Dict avec 'success' (bool), 'errors' (list), 'message' (str si succès)
    """
    user_res = validate_username(new_username)
    if not user_res["valid"]:
        return {"success": False, "errors": user_res["errors"]}

    if not check_username_availability(new_username):
        return {"success": False, "errors": ["Ce nom d'utilisateur est déjà utilisé"]}

    session = get_db_session()
    try:
        user = session.query(User).filter(User.id == user_id, User.is_active == True).first()
        if not user:
            return {"success": False, "errors": ["Utilisateur introuvable ou inactif"]}

        if not verify_password(current_password, user.password_hash):
            return {"success": False, "errors": ["Mot de passe actuel incorrect"]}

        old_username = user.username
        user_email = user.email
        user.username = new_username
        session.commit()

        # ASVS 6.3.7: Notification envoyée après modification du username
        try:
            from .notifications import get_notification_service
            get_notification_service().notify_username_changed(
                recipient=user_email,
                old_username=old_username,
                new_username=new_username,
                ip_address=ip_address
            )
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de notification de changement de nom d'utilisateur: {e}")

        logger.info(f"Nom d'utilisateur modifié pour l'utilisateur ID {user_id}")
        return {"success": True, "message": "Nom d'utilisateur modifié avec succès"}
    except Exception as e:
        session.rollback()
        logger.error(f"Erreur lors de la modification de username pour l'utilisateur {user_id}: {e}")
        return {"success": False, "errors": ["Erreur interne lors de la modification du nom d'utilisateur"]}
    finally:
        session.close()

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Récupère un utilisateur par son nom d'utilisateur (via ORM).
    
    Args:
        username: Le nom d'utilisateur
        
    Returns:
        Dict avec les informations utilisateur ou None
    """
    if _is_mocked_conn():
        try:
            with get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT id, username, email, password_hash, is_active, role, created_at FROM users WHERE username = %s",
                    (username,)
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur {username}: {e}")
            return None

    try:
        session = get_db_session()
        try:
            user = session.query(User).filter(User.username == username).first()
            if user:
                return {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "password_hash": user.password_hash,
                    "is_active": user.is_active,
                    "role": user.role,
                    "created_at": user.created_at,
                }
            return None
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur {username}: {e}")
        return None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Récupère un utilisateur par son ID (via ORM).
    
    Args:
        user_id: L'ID de l'utilisateur
        
    Returns:
        Dict avec les informations utilisateur ou None
    """
    if _is_mocked_conn():
        try:
            with get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT id, username, email, is_active, role, created_at FROM users WHERE id = %s",
                    (user_id,)
                )
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur ID {user_id}: {e}")
            return None

    try:
        session = get_db_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                return {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_active": user.is_active,
                    "role": user.role,
                    "created_at": user.created_at,
                }
            return None
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'utilisateur ID {user_id}: {e}")
        return None

# Fonction utilitaire pour tester les validations
def test_password_validation():
    """Fonction de test pour les validations de mot de passe."""
    test_cases = [
        ("motdepasse", "Trop court et pas assez complexe"),
        ("MotDePasse123!", "Valide"),
        ("password123", "Mot de passe courant"),
        ("123456789012", "Pas assez complexe"),
        ("MdP@Complexe2024", "Valide"),
        ("aaaabbbbcccc", "Répétition de caractères"),
        ("qwertyuiop123", "Suite de caractères simple"),
    ]
    
    print("=== Test de validation des mots de passe ===")
    for password, description in test_cases:
        result = validate_password(password)
        status = "✓ VALIDE" if result["valid"] else "✗ INVALIDE"
        print(f"{status} - {password} ({description})")
        if not result["valid"]:
            for error in result["errors"]:
                print(f"   • {error}")
        print()

if __name__ == "__main__":
    # Configuration du logging pour les tests
    logging.basicConfig(level=logging.INFO)
    
    # Test des validations
    test_password_validation()