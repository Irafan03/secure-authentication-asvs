"""
auth_login.py — Authentification, sessions, rate limiting, contrôle d'accès
ASVS v4.0 — Niveau 2 — P2 : Authentification et protection

Couverture ASVS :
  V2.2  — Limitation des tentatives (rate limiting)
  V2.7  — Vérification sécurisée du mot de passe (bcrypt)
  V3.2  — Gestion de session côté backend (token opaque 32 octets)
  V3.3  — Expiration et invalidation de session
  V2.5  — Pas de comptes par défaut actifs (admin/root)
  V4.1  — Protection des fonctions authentifiées (décorateur)
"""

import os
import secrets
import logging
import functools
from datetime import datetime, timedelta, timezone

import bcrypt
from mysql.connector import Error

from database import get_connection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes de configuration
# ---------------------------------------------------------------------------
MAX_ATTEMPTS        = int(os.environ.get("LOGIN_MAX_ATTEMPTS", 5))
LOCKOUT_WINDOW_MIN  = int(os.environ.get("LOGIN_LOCKOUT_WINDOW_MIN", 15))
SESSION_DURATION_H  = int(os.environ.get("SESSION_DURATION_HOURS", 8))
# Noms réservés qui NE doivent PAS exister en tant que comptes actifs
FORBIDDEN_USERNAMES = {"admin", "root", "administrator", "superuser", "test", "guest"}


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # MySQL DATETIME sans TZ


def _record_attempt(conn, identifier: str, success: bool, ip: str | None) -> None:
    """Enregistre une tentative de connexion dans login_attempts."""
    sql = (
        "INSERT INTO login_attempts (identifier, success, ip_address) "
        "VALUES (%s, %s, %s)"
    )
    cursor = conn.cursor()
    cursor.execute(sql, (identifier.lower(), int(success), ip))
    conn.commit()
    cursor.close()


def _count_recent_failures(conn, identifier: str) -> int:
    """Compte les échecs dans la fenêtre glissante LOCKOUT_WINDOW_MIN."""
    since = _now_utc() - timedelta(minutes=LOCKOUT_WINDOW_MIN)
    sql = (
        "SELECT COUNT(*) FROM login_attempts "
        "WHERE identifier = %s AND success = 0 AND attempted_at >= %s"
    )
    cursor = conn.cursor()
    cursor.execute(sql, (identifier.lower(), since))
    (count,) = cursor.fetchone()
    cursor.close()
    return count


# ---------------------------------------------------------------------------
# 1. Rate limiting / verrouillage
# ---------------------------------------------------------------------------

def is_locked_out(identifier: str) -> bool:
    """
    Retourne True si l'identifiant a dépassé MAX_ATTEMPTS échecs dans
    la fenêtre de LOCKOUT_WINDOW_MIN minutes.

    Protection ASVS V2.2.1 — l'attaquant ne peut pas forcer brutalement.
    """
    try:
        conn = get_connection()
        locked = _count_recent_failures(conn, identifier) >= MAX_ATTEMPTS
        conn.close()
        if locked:
            logger.warning("Compte/IP verrouillé temporairement : %s", identifier)
        return locked
    except Error as exc:
        logger.error("Erreur is_locked_out : %s", exc)
        # En cas d'erreur DB, on refuse par sécurité
        return True


# ---------------------------------------------------------------------------
# 2. Authentification
# ---------------------------------------------------------------------------

def login(username: str, password: str, ip_address: str | None = None) -> dict:
    """
    Vérifie les identifiants et ouvre une session si valide.

    Retourne :
        {"success": True,  "session_token": "<token>", "user_id": <id>}
        {"success": False, "error": "<raison>"}

    ASVS V2.2 — rate limiting
    ASVS V2.7 — vérification bcrypt, pas de timing attack (bcrypt constant-time)
    ASVS V3.2 — token de session opaque, 256 bits
    """
    if not username or not password:
        return {"success": False, "error": "Identifiants manquants."}

    identifier = username.lower()

    # — Rate limiting —
    if is_locked_out(identifier):
        return {
            "success": False,
            "error": (
                f"Compte temporairement verrouillé après {MAX_ATTEMPTS} tentatives. "
                f"Réessayez dans {LOCKOUT_WINDOW_MIN} minutes."
            ),
        }

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Récupérer l'utilisateur (paramètres préparés — pas d'injection SQL)
        cursor.execute(
            "SELECT id, username, password_hash, is_active "
            "FROM users WHERE username = %s LIMIT 1",
            (identifier,),
        )
        user = cursor.fetchone()
        cursor.close()

        # — Vérification intentionnellement constante pour éviter l'énumération —
        # Hash bcrypt valide d'une chaîne aléatoire : utilisé quand l'utilisateur
        # n'existe pas, pour que bcrypt.checkpw s'exécute quand même (timing constant).
        # ASVS V2.7.1 — pas d'énumération par différence de temps de réponse.
        _DUMMY_HASH = b"$2b$12$FwIJVaHGnhg48J.dWQUxseDUf8j7/WD3wnodeiPTXOJiyjYAsn3.O"
        stored_hash = user["password_hash"].encode() if user else _DUMMY_HASH

        password_ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash)

        if not user or not password_ok:
            _record_attempt(conn, identifier, success=False, ip=ip_address)
            conn.close()
            logger.warning("Échec de connexion pour : %s (IP: %s)", identifier, ip_address)
            return {"success": False, "error": "Identifiants incorrects."}

        if not user["is_active"]:
            _record_attempt(conn, identifier, success=False, ip=ip_address)
            conn.close()
            return {"success": False, "error": "Compte désactivé."}

        # — Créer la session —
        session_token = secrets.token_hex(32)          # 256 bits, opaque
        expires_at    = _now_utc() + timedelta(hours=SESSION_DURATION_H)

        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (session_token, user_id, expires_at, ip_address) "
            "VALUES (%s, %s, %s, %s)",
            (session_token, user["id"], expires_at, ip_address),
        )
        conn.commit()
        cursor.close()

        _record_attempt(conn, identifier, success=True, ip=ip_address)
        conn.close()

        logger.info(
            "Connexion réussie — user_id=%s, IP=%s, expire=%s",
            user["id"], ip_address, expires_at,
        )
        return {
            "success":       True,
            "session_token": session_token,
            "user_id":       user["id"],
            "expires_at":    expires_at.isoformat(),
        }

    except Error as exc:
        logger.error("Erreur lors du login : %s", exc)
        return {"success": False, "error": "Erreur interne du serveur."}


# ---------------------------------------------------------------------------
# 3. Validation de session
# ---------------------------------------------------------------------------

def validate_session(session_token: str) -> dict | None:
    """
    Vérifie qu'un token de session est valide (non expiré, non invalidé).

    Retourne les infos utilisateur ou None.
    ASVS V3.2.1 — token opaque, stocké côté serveur.
    ASVS V3.3.1 — expiration obligatoire.
    """
    if not session_token:
        return None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT s.user_id, s.expires_at, s.invalidated, "
            "       u.username, u.role, u.is_active "
            "FROM sessions s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE s.session_token = %s LIMIT 1",
            (session_token,),
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row:
            return None
        if row["invalidated"]:
            return None
        if row["expires_at"] < _now_utc():
            logger.info("Session expirée pour user_id=%s", row["user_id"])
            return None
        if not row["is_active"]:
            return None

        return {
            "user_id":  row["user_id"],
            "username": row["username"],
            "role":     row["role"],
        }

    except Error as exc:
        logger.error("Erreur validate_session : %s", exc)
        return None


# ---------------------------------------------------------------------------
# 4. Déconnexion
# ---------------------------------------------------------------------------

def logout(session_token: str) -> bool:
    """
    Invalide le token de session côté serveur.
    ASVS V3.3.1 — invalidation immédiate à la déconnexion.
    """
    if not session_token:
        return False
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET invalidated = 1 "
            "WHERE session_token = %s AND invalidated = 0",
            (session_token,),
        )
        affected = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Session invalidée (token=***%s)", session_token[-6:])
        return affected > 0
    except Error as exc:
        logger.error("Erreur logout : %s", exc)
        return False


def logout_all(user_id: int) -> int:
    """
    Invalide TOUTES les sessions actives d'un utilisateur (ex: changement de mdp).
    Retourne le nombre de sessions fermées.
    ASVS V3.3.3 — possibilité de révoquer toutes les sessions.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET invalidated = 1 "
            "WHERE user_id = %s AND invalidated = 0",
            (user_id,),
        )
        count = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Toutes sessions invalidées pour user_id=%s (%d sessions)", user_id, count)
        return count
    except Error as exc:
        logger.error("Erreur logout_all : %s", exc)
        return 0


# ---------------------------------------------------------------------------
# 5. Décorateur de protection d'accès
# ---------------------------------------------------------------------------

def require_auth(role: str | None = None):
    """
    Décorateur qui protège une fonction en exigeant une session valide.
    Utilisation :

        @require_auth()
        def get_profile(session_token, ...):
            ...

        @require_auth(role="admin")
        def admin_panel(session_token, ...):
            ...

    Le premier argument positionnel de la fonction décorée DOIT être
    `session_token` (str).

    ASVS V4.1.1 — toutes les routes protégées vérifient l'authentification.
    ASVS V4.1.2 — contrôle de rôle optionnel.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Récupération du token (1er arg ou kwarg)
            token = kwargs.get("session_token") or (args[0] if args else None)
            user_info = validate_session(token)

            if user_info is None:
                return {"error": "Non authentifié.", "status": 401}

            if role and user_info.get("role") != role:
                logger.warning(
                    "Accès refusé — user_id=%s, rôle=%s, rôle requis=%s",
                    user_info["user_id"], user_info["role"], role,
                )
                return {"error": "Accès refusé : privilèges insuffisants.", "status": 403}

            # Injecter les infos utilisateur via kwarg
            kwargs["_user"] = user_info
            return func(*args, **kwargs)

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 6. Vérification absence de comptes par défaut
# ---------------------------------------------------------------------------

def check_no_default_accounts() -> dict:
    """
    Vérifie qu'aucun compte avec un nom réservé (admin, root…) n'est actif.
    ASVS V2.5.6 — pas de credentials par défaut.

    Retourne :
        {"ok": True}  ou  {"ok": False, "found": ["admin", ...]}
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        placeholders = ", ".join(["%s"] * len(FORBIDDEN_USERNAMES))
        cursor.execute(
            f"SELECT username FROM users "
            f"WHERE username IN ({placeholders}) AND is_active = 1",
            tuple(FORBIDDEN_USERNAMES),
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        if rows:
            found = [r[0] for r in rows]
            logger.error("Comptes par défaut actifs détectés : %s", found)
            return {"ok": False, "found": found}

        return {"ok": True}

    except Error as exc:
        logger.error("Erreur check_no_default_accounts : %s", exc)
        return {"ok": False, "found": [], "error": str(exc)}
