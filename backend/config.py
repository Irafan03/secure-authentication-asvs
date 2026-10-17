"""
config.py — Configuration centralisée de la sécurité
ASVS 5.0.0 Niveau 2
"""

from datetime import timedelta
from pathlib import Path
import os

# =============================================================================
# ASVS V6.2 - Paramètres de mot de passe
# =============================================================================

# 6.2.1 : Longueur minimale (≥ 8 requis, 15 recommandé — on retient 12)
PASSWORD_MIN_LENGTH = 12

# 6.2.9 : Longueur maximale (64+ requis par ASVS, on autorise 128)
PASSWORD_MAX_LENGTH = 128

# 6.2.11 : Mots contextuels interdits — chargés depuis un fichier documenté
# Le fichier contextual_words.txt contient un mot par ligne, commentaires (#) ignorés.
# La comparaison est insensible à la casse (substring match).
_CONTEXTUAL_WORDS_FILE = Path(__file__).parent / "contextual_words.txt"


def _load_contextual_words() -> list:
    """Charge les mots contextuels depuis le fichier documenté."""
    words = []
    try:
        with open(_CONTEXTUAL_WORDS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    words.append(line.lower())
    except FileNotFoundError:
        # Fallback minimal si le fichier est absent
        words = ["secureauth", "asvs", "authentication", "login"]
    return words


CONTEXTUAL_WORDS = _load_contextual_words()

# 6.2.4/6.2.12 : Configuration vérification mots de passe compromis
HIBP_API_TIMEOUT = 2.0  # Timeout court pour l'API HIBP (secondes)
HIBP_ENABLED = True  # Activer la vérification HIBP
# 6.2.12 : Comportement si l'API HIBP est indisponible (timeout, erreur réseau, etc.)
# True  = fail-open : le mot de passe est accepté, mais l'événement est journalisé.
#         Les autres contrôles (liste locale, mots contextuels) continuent de s'appliquer.
# False = fail-closed : le mot de passe est refusé.
# Choix retenu : fail-open pour ne pas bloquer l'inscription si l'API est down.
HIBP_FAIL_OPEN = True
LOCAL_COMMON_PASSWORDS_MIN = 3000  # Nombre minimum de mots de passe dans la liste locale

# =============================================================================
# ASVS V6.3 - Rate Limiting (Protection brute force)
# =============================================================================

# 6.3.1 : Rate limiting par IP (protection brute force distribuée)
RATE_LIMIT_IP_MAX_ATTEMPTS = 20 
RATE_LIMIT_IP_WINDOW = timedelta(minutes=15)  
RATE_LIMIT_IP_LOCKOUT = timedelta(minutes=30) 

# 6.3.1 : Rate limiting par (username, IP) (protection ciblée)
RATE_LIMIT_USER_IP_MAX_ATTEMPTS = 5  
RATE_LIMIT_USER_IP_WINDOW = timedelta(minutes=10)  
RATE_LIMIT_USER_IP_LOCKOUT = timedelta(minutes=15) 

# 6.3.1 : Rate limiting par username seul (seuil élevé, ralentissement progressif)
RATE_LIMIT_USERNAME_MAX_ATTEMPTS = 50 
RATE_LIMIT_USERNAME_WINDOW = timedelta(hours=1)  
RATE_LIMIT_USERNAME_DELAY_ENABLED = True 
RATE_LIMIT_USERNAME_DELAY_BASE = 1.0 
RATE_LIMIT_USERNAME_DELAY_MULTIPLIER = 1.5  

# Nettoyage des anciennes tentatives
LOGIN_ATTEMPTS_RETENTION = timedelta(hours=24)

# =============================================================================
# ASVS V6.5 - MFA / TOTP
# =============================================================================

# 6.5.1, 6.5.3 : Configuration TOTP
TOTP_ISSUER = "SecureAuth-ASVS"  # Nom de l'application pour le QR code
TOTP_INTERVAL = 30  # Durée de validité d'un code TOTP (secondes)
TOTP_DIGITS = 6  # Nombre de chiffres du code TOTP
TOTP_ALGORITHM = "SHA1"  # Algorithme (SHA1 standard pour compatibilité)

# 6.5.4 : Entropie minimale (20 bits requis)
TOTP_SECRET_LENGTH = 32  # Longueur du secret en bytes (256 bits >> 20 bits)

# 6.5.1 : Codes de récupération
RECOVERY_CODES_COUNT = 10  # Nombre de codes de récupération générés
RECOVERY_CODE_LENGTH = 8  # Longueur d'un code de récupération (caractères)
RECOVERY_CODE_ENTROPY_BITS = 48  # < 112 bits donc hachage requis (6.5.2)

# =============================================================================
# ASVS V2.4 - Configuration Argon2id
# =============================================================================

ARGON2_TIME_COST = 3  # Iterations
ARGON2_MEMORY_COST = 65536  # Mémoire en KB (64 MB)
ARGON2_PARALLELISM = 4  # Threads parallèles
ARGON2_HASH_LENGTH = 32  # Longueur du hash
ARGON2_SALT_LENGTH = 16  # Longueur du sel

# =============================================================================
# Sessions
# =============================================================================

SESSION_DURATION = timedelta(hours=8)  # Durée de vie d'une session
SESSION_TOKEN_LENGTH = 32  # Longueur du token (bytes)

# ASVS V6.4 — Jetons de récupération
PASSWORD_RESET_TOKEN_TTL = timedelta(minutes=20)
PASSWORD_RESET_URL_BASE = os.environ.get("PASSWORD_RESET_URL_BASE", "http://localhost:5000/password-reset/confirm")
APP_PUBLIC_BASE_URL = os.environ.get("APP_PUBLIC_BASE_URL", "http://localhost:5000")

# =============================================================================
# Sécurité générale & Anti-énumération (6.3.8)
# =============================================================================

# Hash factice pour timing attack protection (6.3.8)
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$fakesaltfakesalt$fakehashfakehashfakehashfakehash"

# Messages génériques identiques quel que soit l'état du compte
RATE_LIMIT_LOCKOUT_MESSAGE = "Trop de tentatives de connexion. Veuillez réessayer plus tard"
INVALID_CREDENTIALS_MESSAGE = "Nom d'utilisateur ou mot de passe incorrect"
REGISTRATION_DUPLICATE_MESSAGE = "Ce nom d'utilisateur ou cette adresse email est déjà utilisé"

# =============================================================================
# ASVS V6.3.5 & V6.3.7 - Notifications de sécurité
# =============================================================================

# Inactivité avant alerte à la reconnexion (ex: 30 jours)
LOGIN_INACTIVITY_THRESHOLD = timedelta(days=30)

# Nombre d'échecs consécutifs avant succès déclenchant une alerte de sécurité
SUSPICIOUS_FAILED_ATTEMPTS_THRESHOLD = 3
