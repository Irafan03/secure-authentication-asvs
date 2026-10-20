"""JSON authentication API consumed by the React frontend."""

from __future__ import annotations

import logging
import os
import secrets
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, g, jsonify, make_response, request, send_from_directory

from .auth_login import authenticate_user, check_rate_limit, logout_user, record_login_attempt, validate_session
from .auth_mfa import (
    enroll_mfa,
    get_totp_secret,
    is_mfa_enabled,
    validate_mfa_enrollment,
    verify_recovery_code,
    verify_totp_code,
)
from .auth_register import change_password, register_user, validate_password, verify_password
from .config import SESSION_DURATION
from .database import init_db
from .models import (
    MfaRecoveryCode,
    MfaReenrollment,
    MfaSecret,
    Session as SessionModel,
    TotpUsedCode,
    User,
    get_db_session,
    init_db_orm,
)
from sqlalchemy import or_
from .password_recovery import (
    complete_mfa_recovery,
    complete_password_reset,
    request_mfa_recovery,
    request_password_reset,
)


PROJECT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = PROJECT_DIR / "frontend" / "dist"
AUTH_COOKIE = "secureauth_session"
COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SESSION_SECRET_KEY") or secrets.token_urlsafe(32)
app.config.update(
    SESSION_COOKIE_NAME="secureauth_flask_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
)

_database_initialized = False


@app.before_request
def initialize_database_once() -> None:
    """Try schema initialization once; public frontend pages stay available offline."""
    global _database_initialized
    if _database_initialized:
        return
    _database_initialized = True
    try:
        init_db()
        init_db_orm()
        logger.info("Base de données initialisée")
    except Exception:
        logger.exception("Impossible d'initialiser la base de données")


def json_error(message: str, status: int, *, errors: list[str] | None = None):
    payload: dict[str, Any] = {"success": False, "errors": errors or [message], "message": message}
    return no_store(make_response(jsonify(payload), status))


def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def current_user() -> dict[str, Any] | None:
    token = request.cookies.get(AUTH_COOKIE)
    if not token:
        return None
    return validate_session(token)


def login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            response = make_response(jsonify({"authenticated": False, "success": False, "errors": ["Authentification requise."]}), 401)
            return no_store(response)
        g.auth_user = user
        mfa_setup_endpoints = {"api_mfa_enrollment", "api_mfa_enrollment_confirm"}
        if (not user.get("mfa_enabled") or not user.get("mfa_verified")) and request.endpoint not in mfa_setup_endpoints:
            return json_error(
                "La double authentification est obligatoire. Configurez la MFA pour continuer.",
                403,
            )
        return view(*args, **kwargs)

    return wrapped


def admin_required(view: Callable):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.auth_user.get("role") != "admin":
            return json_error("Accès refusé.", 403)
        return view(*args, **kwargs)

    return wrapped


def set_auth_cookie(response, token: str):
    response.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=int(SESSION_DURATION.total_seconds()),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Lax",
        path="/",
    )
    return no_store(response)


def clear_auth_cookie(response):
    response.delete_cookie(AUTH_COOKIE, path="/", httponly=True, secure=COOKIE_SECURE, samesite="Lax")
    return no_store(response)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "SecureAuth API"})


@app.post("/register")
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Corps JSON requis.", 400)
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    password_confirm = data.get("password_confirm")
    if not all(isinstance(value, str) and value for value in (username, email, password, password_confirm)):
        return json_error("Tous les champs sont requis.", 400)
    if password != password_confirm:
        return json_error("Les mots de passe ne correspondent pas.", 400)
    result = register_user(username.strip(), email.strip(), password)
    if result.get("success"):
        status = 201
    elif result.get("error_code") == "database_unavailable":
        status = 503
    else:
        status = 400
    return no_store(make_response(jsonify(result), status))


@app.post("/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Corps JSON requis.", 400)
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
        return json_error("Nom d'utilisateur ou adresse e-mail et mot de passe requis.", 400)
    result = authenticate_user(
        username=username.strip(),
        password=password,
        ip_address=request.remote_addr or "unknown",
        user_agent=request.user_agent.string or "unknown",
        totp_code=data.get("totp_code") or None,
        recovery_code=data.get("recovery_code") or None,
    )
    if result.get("success"):
        previous_token = request.cookies.get(AUTH_COOKIE)
        if previous_token:
            logout_user(previous_token)
        response = make_response(jsonify({
            "success": True,
            "user": result["user"],
            "mfa_enrollment_required": result.get("mfa_enrollment_required", False),
        }))
        return set_auth_cookie(response, result["session_token"])
    if result.get("mfa_required"):
        response = make_response(jsonify({
            "success": False,
            "mfa_required": True,
            "errors": result.get("errors", ["Un second facteur est requis."]),
        }), 200)
        return no_store(response)
    if result.get("locked_until"):
        response = make_response(jsonify({
            "success": False,
            "errors": result.get("errors", ["Trop de tentatives. Réessayez plus tard."]),
            "locked_until": result["locked_until"].isoformat() if hasattr(result["locked_until"], "isoformat") else str(result["locked_until"]),
        }), 423)
        return no_store(response)
    return json_error("Identifiant ou mot de passe incorrect.", 401, errors=result.get("errors"))


@app.get("/api/auth/session")
def auth_session():
    user = current_user()
    if not user:
        response = make_response(jsonify({"authenticated": False}), 401)
        return clear_auth_cookie(response) if request.cookies.get(AUTH_COOKIE) else no_store(response)
    if user.get("mfa_enabled") and not user.get("mfa_verified"):
        token = request.cookies.get(AUTH_COOKIE, "")
        if token:
            logout_user(token)
        return clear_auth_cookie(make_response(jsonify({"authenticated": False}), 401))
    response = make_response(jsonify({
        "authenticated": True,
        "user": {
            "id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "mfa_enabled": bool(user.get("mfa_enabled", False)),
            "mfa_enrollment_required": not bool(user.get("mfa_enabled", False)),
        },
    }))
    return no_store(response)


@app.post("/api/auth/logout")
def auth_logout():
    token = request.cookies.get(AUTH_COOKIE)
    if token:
        logout_user(token)
    response = make_response(jsonify({"success": True, "message": "Déconnexion réussie."}))
    return clear_auth_cookie(response)


@app.post("/api/validate-password")
def api_validate_password():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("password"), str):
        return json_error("Mot de passe requis.", 400)
    result = validate_password(data["password"], data.get("username", ""))
    return no_store(make_response(jsonify(result)))


@app.post("/api/account/password")
@login_required
def api_change_password():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Corps JSON requis.", 400)
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    if not isinstance(current_password, str) or not current_password or not isinstance(new_password, str) or not new_password:
        return json_error("Mot de passe actuel et nouveau mot de passe requis.", 400)
    result = change_password(
        g.auth_user["user_id"], current_password, new_password, request.remote_addr or "unknown"
    )
    if not result.get("success"):
        return json_error("Le mot de passe n'a pas pu être modifié.", 400, errors=result.get("errors"))

    # Revoke other sessions while keeping the session used to change the password.
    db = None
    try:
        db = get_db_session()
        db.query(SessionModel).filter(
            SessionModel.user_id == g.auth_user["user_id"],
            SessionModel.session_token != request.cookies.get(AUTH_COOKIE),
        ).update({SessionModel.invalidated: True}, synchronize_session=False)
        db.commit()
    except Exception:
        if db is not None:
            db.rollback()
        logger.exception("Impossible de révoquer les autres sessions après un changement de mot de passe")
    finally:
        if db is not None:
            db.close()
    return no_store(make_response(jsonify(result)))


@app.post("/api/account/mfa/enrollment")
@login_required
def api_mfa_enrollment():
    user = g.auth_user
    if is_mfa_enabled(user["user_id"]):
        return json_error("L'authentification MFA est déjà activée.", 409)
    try:
        result = enroll_mfa(user["user_id"], user["username"])
    except Exception:
        logger.exception("Échec de l'initialisation de l'enrôlement MFA")
        return json_error("Impossible de démarrer l'enrôlement MFA.", 500)
    response = make_response(jsonify({
        "success": True,
        "secret": result["secret"],
        "qr_code_uri": result["qr_code_uri"],
        "recovery_codes": result["recovery_codes"],
    }))
    return no_store(response)


@app.post("/api/account/mfa/enrollment/confirm")
@login_required
def api_mfa_enrollment_confirm():
    data = request.get_json(silent=True)
    code = data.get("totp_code", "").strip() if isinstance(data, dict) and isinstance(data.get("totp_code"), str) else ""
    if not code:
        return json_error("Code TOTP requis.", 400)
    ip_address = request.remote_addr or "unknown"
    rate_identifier = f"mfa-enrollment:{g.auth_user['user_id']}"
    rate = check_rate_limit(rate_identifier, ip_address)
    if not rate.get("allowed"):
        return json_error(rate.get("reason", "Trop de tentatives."), 423)
    if not validate_mfa_enrollment(g.auth_user["user_id"], code):
        record_login_attempt(rate_identifier, ip_address, False)
        return json_error("Code TOTP invalide ou expiré.", 400)
    record_login_attempt(rate_identifier, ip_address, True)
    if not validate_session(request.cookies.get(AUTH_COOKIE, "")):
        response = make_response(jsonify({
            "success": True,
            "reauthentication_required": True,
            "message": "MFA activée. Reconnectez-vous pour terminer la récupération du compte.",
        }))
        return clear_auth_cookie(response)
    session_token = request.cookies.get(AUTH_COOKIE, "")
    db = get_db_session()
    try:
        active_session = db.query(SessionModel).filter(
            SessionModel.session_token == session_token,
            SessionModel.user_id == g.auth_user["user_id"],
            SessionModel.invalidated.is_(False),
        ).first()
        if not active_session:
            return json_error("Reconnectez-vous pour terminer l’activation de la MFA.", 401)
        active_session.mfa_verified = True
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Impossible de finaliser la session après l'activation MFA")
        return json_error("La MFA est activée. Reconnectez-vous pour continuer.", 500)
    finally:
        db.close()
    response = make_response(jsonify({"success": True, "message": "Authentification MFA activée."}))
    return no_store(response)


@app.post("/api/account/mfa/disable")
@login_required
def api_mfa_disable():
    return json_error("La double authentification est obligatoire et ne peut pas être désactivée.", 403)


@app.post("/password-reset")
def password_reset_request():
    data = request.get_json(silent=True)
    identifier = data.get("identifier", "") if isinstance(data, dict) else ""
    result = request_password_reset(identifier, request.remote_addr or "unknown")
    return no_store(make_response(jsonify(result)))


@app.post("/password-reset/confirm")
def password_reset_confirm():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Corps JSON requis.", 400)
    result = complete_password_reset(
        data.get("token", ""),
        data.get("new_password", ""),
        request.remote_addr or "unknown",
        data.get("totp_code"),
        data.get("recovery_code"),
    )
    status = 200 if result.get("success") else 400
    response = make_response(jsonify(result), status)
    return clear_auth_cookie(response) if result.get("success") else no_store(response)


@app.post("/mfa/recovery/request")
def mfa_recovery_request():
    data = request.get_json(silent=True)
    identifier = data.get("identifier", "").strip() if isinstance(data, dict) and isinstance(data.get("identifier", ""), str) else ""
    ip_address = request.remote_addr or "unknown"
    # Apply a shared identifier/IP limit and record every request before account lookup.
    allowed = check_rate_limit(identifier or "unknown", ip_address)
    record_login_attempt(identifier or "unknown", ip_address, False)
    if identifier and allowed.get("allowed"):
        db = None
        try:
            db = get_db_session()
            user = db.query(User).filter(
                User.is_active.is_(True),
                or_(User.username == identifier, User.email == identifier.lower()),
            ).first()
            if user and user.mfa_enabled:
                request_mfa_recovery(user.id, ip_address)
        except Exception:
            logger.exception("MFA recovery request could not be completed")
        finally:
            if db is not None:
                db.close()
    return no_store(make_response(jsonify({
        "success": True,
        "message": "Si le compte peut être récupéré, les instructions ont été envoyées.",
    })))


@app.post("/mfa/recovery/confirm")
def mfa_recovery_confirm():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Corps JSON requis.", 400)
    ok = complete_mfa_recovery(
        None, data.get("token", ""), data.get("current_password", ""),
        request.remote_addr or "unknown",
    )
    if not ok:
        return json_error("Demande invalide ou expirée.", 400)
    response = make_response(jsonify({
        "success": True,
        "message": "MFA réinitialisé. Reconnectez-vous pour enrôler un nouveau facteur.",
    }))
    return clear_auth_cookie(response)


@app.post("/admin/users/<int:user_id>/password-reset")
@admin_required
def admin_password_reset_request(user_id: int):
    request_password_reset(
        "", request.remote_addr or "unknown", initiated_by="admin",
        initiated_by_user_id=g.auth_user["user_id"], target_user_id=user_id,
    )
    return no_store(make_response(jsonify({
        "success": True,
        "message": "Si le compte existe, les instructions ont été envoyées.",
    })))


@app.get("/")
@app.get("/<path:frontend_path>")
def frontend(frontend_path: str = ""):
    """Serve the built React SPA when present; use Vite on port 5173 in development."""
    if FRONTEND_DIST.is_dir() and (FRONTEND_DIST / "index.html").is_file():
        requested_file = FRONTEND_DIST / frontend_path
        if frontend_path and requested_file.is_file() and FRONTEND_DIST in requested_file.resolve().parents:
            return send_from_directory(FRONTEND_DIST, frontend_path)
        return send_from_directory(FRONTEND_DIST, "index.html")
    if not frontend_path:
        return jsonify({"service": "SecureAuth API", "frontend": "Run npm run dev --prefix frontend"})
    return jsonify({"success": False, "errors": ["Ressource introuvable."]}), 404


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"success": False, "errors": ["Ressource introuvable."]}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error("Erreur API: %s", error)
    return jsonify({"success": False, "errors": ["Erreur interne."]}), 500


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "true").lower() == "true", host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
