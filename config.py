"""
config.py — Configuration centralisée de la sécurité
ASVS 5.0.0 Niveau 2
"""

from datetime import timedelta

# =============================================================================
# ASVS V6.2 - Paramètres de mot de passe
# =============================================================================

# 6.2.1 : Longueur minimale 
PASSWORD_MIN_LENGTH = 12

# 6.2.9 : Longueur maximale (64+ requis)
PASSWORD_MAX_LENGTH = 128

# 6.2.11 : Mots contextuels interdits (nom projet, organisation, etc.)
CONTEXTUAL_WORDS = [
    "secure", "authentication", "asvs", "auth", "login",
    "secureauth", "secureauthentication", "mycompany", "myapp"
]

# 6.2.4/6.2.12 : Configuration vérification mots de passe compromis
HIBP_API_TIMEOUT = 2.0  # Timeout court pour l'API HIBP (secondes)
HIBP_ENABLED = True  # Activer la vérification HIBP
HIBP_FAIL_OPEN = True  # Si API indisponible, autoriser (True) ou refuser (False)
LOCAL_COMMON_PASSWORDS_MIN = 3000  # Nombre minimum de mots de passe dans la liste locale

# =============================================================================
# ASVS V6.3 - Rate Limiting (Protection brute force)
# =============================================================================

# 6.3.1 : Rate limiting par IP (protection brute force distribuée)
RATE_LIMIT_IP_MAX_ATTEMPTS = 20  # Tentatives max par IP
RATE_LIMIT_IP_WINDOW = timedelta(minutes=15)  # Fenêtre de temps IP
RATE_LIMIT_IP_LOCKOUT = timedelta(minutes=30)  # Durée de blocage IP

# 6.3.1 : Rate limiting par (username, IP) (protection ciblée)
RATE_LIMIT_USER_IP_MAX_ATTEMPTS = 5  # Tentatives max par couple (user, IP)
RATE_LIMIT_USER_IP_WINDOW = timedelta(minutes=10)  # Fenêtre de temps
RATE_LIMIT_USER_IP_LOCKOUT = timedelta(minutes=15)  # Durée de blocage

# 6.3.1 : Rate limiting par username seul (seuil élevé, ralentissement progressif)
RATE_LIMIT_USERNAME_MAX_ATTEMPTS = 50  # Seuil très élevé (évite DoS)
RATE_LIMIT_USERNAME_WINDOW = timedelta(hours=1)  # Fenêtre de temps large
RATE_LIMIT_USERNAME_DELAY_ENABLED = True  # Activer délai progressif
RATE_LIMIT_USERNAME_DELAY_BASE = 1.0  # Délai de base en secondes
RATE_LIMIT_USERNAME_DELAY_MULTIPLIER = 1.5  # Multiplicateur par tentative

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

# =============================================================================
# Sécurité générale
# =============================================================================

# Hash factice pour timing attack protection (6.3.8)
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$fakesaltfakesalt$fakehashfakehashfakehashfakehash"
