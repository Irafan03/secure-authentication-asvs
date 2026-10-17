"""
auth_register.py — Inscription sécurisée conforme ASVS 5.0.0 Niveau 2
Validation des mots de passe selon ASVS V6.2.1 à V6.2.5
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
from database import get_connection
from config import HIBP_API_TIMEOUT, HIBP_ENABLED, HIBP_FAIL_OPEN, CONTEXTUAL_WORDS
import mysql.connector

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

# Cache pour la liste des mots de passe courants (ASVS V6.2.5)
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
    
    ASVS 6.2.4 / 6.2.12: Utilise la méthode k-anonymity (envoie seulement les 5 premiers
    caractères du SHA-1) pour préserver la confidentialité du mot de passe.
    
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
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=HIBP_API_TIMEOUT)
        
        if response.status_code == 200:
            # Chercher le suffixe dans la réponse
            hashes = response.text.splitlines()
            for line in hashes:
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
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
    if len(username) < 3:
        errors.append("Le nom d'utilisateur doit contenir au moins 3 caractères")
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
        # Validation avec email-validator
        valid_email = validate_email(email)
        normalized_email = valid_email.email
        
        # Longueur maximale
        if len(normalized_email) > 255:
            errors.append("L'adresse email ne peut pas dépasser 255 caractères")
        
        return {"valid": len(errors) == 0, "errors": errors, "normalized": normalized_email}
        
    except EmailNotValidError as e:
        errors.append(f"Adresse email invalide: {str(e)}")
        return {"valid": False, "errors": errors}

def validate_password(password: str, username: str = None) -> Dict[str, Any]:
    """
    Valide le mot de passe selon les exigences ASVS V6.2.1 à V6.2.5.
    
    Args:
        password: Le mot de passe à valider
        username: Le nom d'utilisateur (pour éviter la réutilisation)
        
    Returns:
        Dict avec 'valid' (bool) et 'errors' (list)
    """
    errors = []
    
    if not password:
        errors.append("Le mot de passe est requis")
        return {"valid": False, "errors": errors}
    
    
    if len(password) < 12:
        errors.append("Le mot de passe doit contenir au moins 12 caractères")
    



    # Longueur maximale raisonnable (pour éviter les attaques DoS)
    if len(password) > 128:
        errors.append("Le mot de passe ne peut pas dépasser 128 caractères")

        
    
    # ASVS V6.2.5: Pas de règles de composition (types de caractères imposés) - SUPPRIMÉ
    # Seules les contraintes de longueur min/max sont conservées
    
    # ASVS V6.2.3: Le mot de passe ne doit pas être le nom d'utilisateur
    if username and password.lower() == username.lower():
        errors.append("Le mot de passe ne peut pas être identique au nom d'utilisateur")
    
    # ASVS V6.2.4: Supprimé - pas de règles de composition
    
    # ASVS 6.2.11 / 6.1.2: Vérification des mots contextuels interdits
    password_lower = password.lower()
    for word in CONTEXTUAL_WORDS:
        if word.lower() in password_lower:
            errors.append(f"Le mot de passe ne peut pas contenir des mots liés au contexte de l'application")
            break
    
    #  Vérification contre la liste des mots de passe compromis
    common_passwords = load_common_passwords()
    if password.lower() in common_passwords:
        errors.append("Ce mot de passe fait partie des mots de passe couramment utilisés et n'est pas sécurisé")
    
    # Vérification via API Have I Been Pwned (k-anonymity)
    if not check_password_pwned(password):
        errors.append("Ce mot de passe a été compromis dans des fuites de données et n'est pas sécurisé")
    
    # Vérifications supplémentaires de sécurité - SUPPRIMÉ
    # (Les suites simples sont déjà dans la liste des mots de passe compromis)
    
    return {"valid": len(errors) == 0, "errors": errors}

def hash_password(password: str) -> str:
    """
    Hache un mot de passe avec Argon2id.
    
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

def check_username_availability(username: str) -> bool:
    """
    Vérifie si le nom d'utilisateur est disponible.
    
    Args:
        username: Le nom d'utilisateur à vérifier
        
    Returns:
        True si disponible, False sinon
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
            return cursor.fetchone() is None
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de la disponibilité du nom d'utilisateur: {e}")
        return False

def check_email_availability(email: str) -> bool:
    """
    Vérifie si l'adresse email est disponible.
    
    Args:
        email: L'adresse email à vérifier
        
    Returns:
        True si disponible, False sinon
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE email = %s", (email,))
            return cursor.fetchone() is None
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
    
    # Insérer l'utilisateur en base de données
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            insert_query = """
            INSERT INTO users (username, email, password_hash)
            VALUES (%s, %s, %s)
            """
            
            cursor.execute(insert_query, (username, normalized_email, password_hash))
            conn.commit()
            
            user_id = cursor.lastrowid
            
            logger.info(f"Nouvel utilisateur inscrit: {username} (ID: {user_id})")
            
            return {
                "success": True,
                "user_id": user_id,
                "message": "Inscription réussie"
            }
            
    except mysql.connector.IntegrityError as e:
        # Gestion des contraintes d'unicité (race condition)
        # ASVS 6.3.8: Message générique pour éviter l'énumération
        logger.error(f"Erreur d'intégrité lors de l'inscription: {e}")
        return {"success": False, "errors": ["Ce nom d'utilisateur ou cette adresse email est déjà utilisé"]}
    
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription de {username}: {e}")
        return {"success": False, "errors": ["Erreur interne lors de la création du compte"]}

def change_password(user_id: int, current_password: str, new_password: str) -> Dict[str, Any]:
    errors = []
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # Récupérer l'utilisateur et son hash actuel
            cursor.execute(
                "SELECT username, password_hash FROM users WHERE id = %s AND is_active = 1",
                (user_id,))
            result = cursor.fetchone()
            if not result:
                return {"success": False, "errors": ["Utilisateur introuvable ou inactif"]}
            username, current_hash = result
            # Vérifier le mot de passe actuel
            if not verify_password(current_password, current_hash):
                return {"success": False, "errors": ["Mot de passe actuel incorrect"]}
            # Vérifier que le nouveau mot de passe est différent de l'ancien
            if verify_password(new_password, current_hash):
                return {"success": False, "errors": ["Le nouveau mot de passe doit être différent de l'ancien"]}
            # Valider le nouveau mot de passe
            password_validation = validate_password(new_password, username)
            if not password_validation["valid"]:
                return {"success": False, "errors": password_validation["errors"]}            
            # Hacher le nouveau mot de passe
            try:
                new_hash = hash_password(new_password)
            except HashingError:
                return {"success": False, "errors": ["Erreur lors de la création du nouveau mot de passe"]}
            # Mettre à jour le mot de passe en base
            cursor.execute(
                "UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (new_hash, user_id)
            )
            conn.commit()
            logger.info(f"Mot de passe changé pour l'utilisateur ID {user_id}")
            return {"success": True, "message": "Mot de passe changé avec succès"}
            
    except Exception as e:
        logger.error(f"Erreur lors du changement de mot de passe pour l'utilisateur {user_id}: {e}")
        return {"success": False, "errors": ["Erreur interne lors du changement de mot de passe"]}

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Récupère un utilisateur par son nom d'utilisateur.
    
    Args:
        username: Le nom d'utilisateur
        
    Returns:
        Dict avec les informations utilisateur ou None
    """
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

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Récupère un utilisateur par son ID.
    
    Args:
        user_id: L'ID de l'utilisateur
        
    Returns:
        Dict avec les informations utilisateur ou None
    """
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