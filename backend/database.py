"""
database.py — Pool de connexions MySQL et initialisation des tables
ASVS v4.0 — Niveau 2
"""

import os
import logging
from pathlib import Path

from dotenv import load_dotenv
import mysql.connector
from mysql.connector import pooling, Error

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# Load project settings by absolute path, regardless of the shell's current directory.
load_dotenv(Path(__file__).resolve().parent / ".env", override=False)

# ---------------------------------------------------------------------------
# Configuration (variables d'environnement, jamais en dur)
# ---------------------------------------------------------------------------
DB_CONFIG = {
    "host":     os.environ.get("DB_HOST", "localhost"),
    "port":     int(os.environ.get("DB_PORT", 3306)),
    "user":     os.environ.get("DB_USER", "app_user"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "secure_auth"),
    "charset":  "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
    "use_unicode": True,
    "connection_timeout": 10,
}

POOL_CONFIG = {
    "pool_name": "auth_pool",
    "pool_size": 5,
    "pool_reset_session": True,
}

_pool: pooling.MySQLConnectionPool | None = None


def get_pool() -> pooling.MySQLConnectionPool:
    """Retourne (ou crée) le pool de connexions."""
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(**POOL_CONFIG, **DB_CONFIG)
        logger.info("Pool de connexions MySQL initialisé.")
    return _pool


def get_connection():
    """Fournit une connexion issue du pool (utiliser avec `with`)."""
    return get_pool().get_connection()


# ---------------------------------------------------------------------------
# Initialisation du schéma
# ---------------------------------------------------------------------------
SCHEMA_SQL = [
    # Table users — créée par auth_register (P1), on la recrée si absente
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        username      VARCHAR(64)  NOT NULL UNIQUE,
        email         VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        is_active     TINYINT(1)   NOT NULL DEFAULT 1,
        mfa_enabled   TINYINT(1)   NOT NULL DEFAULT 0,
        role          ENUM('user','admin') NOT NULL DEFAULT 'user',
        created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                      ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des tentatives de connexion (rate limiting multi-niveaux)
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        identifier  VARCHAR(255) NOT NULL,          -- IP, username, ou user:IP
        identifier_type ENUM('ip', 'username', 'user_ip') NOT NULL DEFAULT 'username',
        attempted_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        success     TINYINT(1)   NOT NULL DEFAULT 0,
        ip_address  VARCHAR(45),
        INDEX idx_identifier_type_time (identifier, identifier_type, attempted_at),
        INDEX idx_ip_time (ip_address, attempted_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des sessions backend (sans cookie côté web)
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_token  CHAR(64)     NOT NULL PRIMARY KEY,
        user_id        INT UNSIGNED NOT NULL,
        created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at     DATETIME     NOT NULL,
        invalidated    TINYINT(1)   NOT NULL DEFAULT 0,
        mfa_verified   TINYINT(1)   NOT NULL DEFAULT 0,
        ip_address     VARCHAR(45),
        CONSTRAINT fk_session_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des secrets TOTP (MFA)
    """
    CREATE TABLE IF NOT EXISTS mfa_secrets (
        user_id       INT UNSIGNED NOT NULL PRIMARY KEY,
        totp_secret   VARCHAR(255) NOT NULL,
        validated     TINYINT(1)   NOT NULL DEFAULT 0,
        validated_at  DATETIME,
        created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_mfa_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des codes de récupération MFA (hachés)
    """
    CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
        id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id    INT UNSIGNED NOT NULL,
        code_hash  VARCHAR(255) NOT NULL,
        used       TINYINT(1)   NOT NULL DEFAULT 0,
        used_at    DATETIME,
        created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_recovery_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_unused (user_id, used)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des codes TOTP utilisés (anti-rejeu)
    """
    CREATE TABLE IF NOT EXISTS totp_used_codes (
        id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id    INT UNSIGNED NOT NULL,
        code_hash  CHAR(64)     NOT NULL,
        used_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_totp_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_code_time (user_id, code_hash, used_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des appareils connus / empreintes (ASVS 6.3.5)
    """
    CREATE TABLE IF NOT EXISTS user_devices (
        id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id    INT UNSIGNED NOT NULL,
        ip_address VARCHAR(45)  NOT NULL,
        user_agent VARCHAR(512) NOT NULL,
        first_seen DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_device_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_device_ip (user_id, ip_address),
        INDEX idx_user_device_full (user_id, ip_address, user_agent(255))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
]


def init_db() -> None:
    """Crée les tables si elles n'existent pas encore."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        for stmt in SCHEMA_SQL:
            if "ADD COLUMN IF NOT EXISTS mfa_enabled" in stmt:
                continue
            cursor.execute(stmt)
<<<<<<< HEAD:backend/database.py
        # S'assurer que mfa_enabled et last_login_at existent
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN mfa_enabled TINYINT(1) NOT NULL DEFAULT 0")
        except Error:
            pass  # Déjà présente ou erreur ignorée
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_at DATETIME NULL")
        except Error:
            pass  # Déjà présente ou erreur ignorée
=======
        # `ADD COLUMN IF NOT EXISTS` is not supported by every MySQL version.
        cursor.execute("SHOW COLUMNS FROM users LIKE 'mfa_enabled'")
        if cursor.fetchone() is None:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN mfa_enabled TINYINT(1) NOT NULL DEFAULT 0"
            )
>>>>>>> 68f20a7 (frontend):database.py
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Schéma de base de données initialisé avec succès.")
    except Error as exc:
        logger.error("Erreur lors de l'initialisation du schéma : %s", exc)
        raise
