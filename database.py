"""
database.py — Pool de connexions MySQL et initialisation des tables
ASVS v4.0 — Niveau 2
"""

import os
import logging
import mysql.connector
from mysql.connector import pooling, Error

logger = logging.getLogger(__name__)

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
        role          ENUM('user','admin') NOT NULL DEFAULT 'user',
        created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                      ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # Table des tentatives de connexion (rate limiting)
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        identifier  VARCHAR(255) NOT NULL,          -- username ou IP
        attempted_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        success     TINYINT(1)   NOT NULL DEFAULT 0,
        ip_address  VARCHAR(45),
        INDEX idx_identifier_time (identifier, attempted_at)
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
        ip_address     VARCHAR(45),
        CONSTRAINT fk_session_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
]


def init_db() -> None:
    """Crée les tables si elles n'existent pas encore."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        for stmt in SCHEMA_SQL:
            cursor.execute(stmt)
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Schéma de base de données initialisé avec succès.")
    except Error as exc:
        logger.error("Erreur lors de l'initialisation du schéma : %s", exc)
        raise
