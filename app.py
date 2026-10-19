"""FastAPI web interface for the SecureAuth authentication backend."""

from __future__ import annotations

import base64
import hmac
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from auth_login import authenticate_user, logout_user, validate_session
from auth_mfa import (
    enroll_mfa,
    generate_qr_code,
    validate_mfa_enrollment,
)
from auth_register import change_password, register_user, validate_password
from database import init_db


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY")
if not SESSION_SECRET_KEY:
    SESSION_SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("SESSION_SECRET_KEY non définie : une clé temporaire est utilisée pour ce démarrage")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Initialize MySQL once when the ASGI application starts."""
    try:
        await run_in_threadpool(init_db)
        logger.info("Base de données initialisée")
    except Exception:
        # Keep the home and documentation pages available when MySQL is down.
        # Authentication routes will report backend errors through their usual flow.
        logger.exception("Erreur lors de l'initialisation de la base de données")
    yield


app = FastAPI(
    title="SecureAuth",
    description="Interface d'authentification sécurisée",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="secureauth_session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)


def add_flash(request: Request, message: str, category: str = "info") -> None:
    messages = request.session.setdefault("_flash_messages", [])
    messages.append((category, message))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def template_context(request: Request) -> dict[str, Any]:
    def get_flashed_messages(with_categories: bool = False):
        messages = request.session.pop("_flash_messages", [])
        if with_categories:
            return messages
        return [message for _category, message in messages]

    def url_for(endpoint: str, **values: Any):
        # Translate the existing Jinja `filename=` form into Starlette's `path=`.
        if endpoint == "static" and "filename" in values:
            values["path"] = values.pop("filename")
        return request.url_for(endpoint, **values)

    return {
        "csrf_token": csrf_token(request),
        "get_flashed_messages": get_flashed_messages,
        "session": request.session,
        "url_for": url_for,
    }


templates.context_processors.append(template_context)


def render_page(
    request: Request,
    name: str,
    *,
    status_code: int = 200,
    **context: Any,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=context,
        status_code=status_code,
    )


def redirect_to(request: Request, endpoint: str, *, status_code: int = 303) -> RedirectResponse:
    return RedirectResponse(request.url_for(endpoint), status_code=status_code)


async def require_csrf(request: Request, form: Any) -> None:
    expected = request.session.get("csrf_token", "")
    submitted = str(form.get("csrf_token", ""))
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        raise HTTPException(status_code=400, detail="Jeton CSRF invalide ou expiré.")


async def require_session(request: Request) -> dict[str, Any]:
    token = request.session.get("session_token")
    if not token:
        add_flash(request, "Veuillez vous connecter pour accéder à cette page.", "warning")
        raise HTTPException(status_code=303, headers={"Location": str(request.url_for("login"))})

    session_data = await run_in_threadpool(validate_session, token)
    if not session_data:
        request.session.clear()
        add_flash(request, "Votre session a expiré. Veuillez vous reconnecter.", "warning")
        raise HTTPException(status_code=303, headers={"Location": str(request.url_for("login"))})
    return session_data


@app.exception_handler(404)
async def not_found(request: Request, _exc: Exception) -> HTMLResponse:
    return render_page(request, "404.html", status_code=404)


@app.exception_handler(400)
async def bad_request(request: Request, _exc: Exception) -> HTMLResponse:
    return render_page(request, "400.html", status_code=400)


@app.exception_handler(500)
async def internal_error(request: Request, exc: Exception) -> HTMLResponse:
    logger.error("Erreur serveur: %s", exc)
    return render_page(request, "500.html", status_code=500)


@app.get("/", response_class=HTMLResponse, name="index")
async def index(request: Request) -> Response:
    if request.session.get("session_token"):
        return redirect_to(request, "dashboard")
    return render_page(request, "index.html")


@app.get("/register", response_class=HTMLResponse, name="register")
async def register_page(request: Request) -> HTMLResponse:
    return render_page(request, "register.html")


@app.post("/register", response_class=HTMLResponse, name="register_submit")
async def register_submit(request: Request) -> Response:
    form = await request.form()
    await require_csrf(request, form)
    username = str(form.get("username", "")).strip()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    password_confirm = str(form.get("password_confirm", ""))

    if not all((username, email, password, password_confirm)):
        add_flash(request, "Tous les champs sont requis.", "danger")
        return render_page(request, "register.html", status_code=400)
    if password != password_confirm:
        add_flash(request, "Les mots de passe ne correspondent pas.", "danger")
        return render_page(request, "register.html", status_code=400)

    result = await run_in_threadpool(register_user, username, email, password)
    if result["success"]:
        add_flash(request, "Compte créé avec succès. Vous pouvez maintenant vous connecter.", "success")
        return redirect_to(request, "login")
    for error in result.get("errors", []):
        add_flash(request, error, "danger")
    return render_page(request, "register.html", status_code=400)


@app.get("/login", response_class=HTMLResponse, name="login")
async def login_page(request: Request) -> HTMLResponse:
    return render_page(request, "login.html")


@app.post("/login", response_class=HTMLResponse, name="login_submit")
async def login_submit(request: Request) -> Response:
    form = await request.form()
    await require_csrf(request, form)
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    totp_code = str(form.get("totp_code", "")).strip()
    if not username or not password:
        add_flash(request, "Nom d'utilisateur et mot de passe requis.", "danger")
        return render_page(request, "login.html", status_code=400)

    ip_address = request.client.host if request.client else "unknown"
    result = await run_in_threadpool(
        authenticate_user,
        username=username,
        password=password,
        ip_address=ip_address,
        totp_code=totp_code or None,
    )
    if result["success"]:
        request.session.clear()
        request.session["session_token"] = result["session_token"]
        request.session["username"] = result["user"]["username"]
        request.session["user_id"] = result["user"]["id"]
        add_flash(request, f"Bienvenue, {result['user']['username']} !", "success")
        return redirect_to(request, "dashboard")

    if result.get("mfa_required"):
        request.session["pending_username"] = username
        add_flash(request, "Veuillez entrer votre code d'authentification à deux facteurs.", "info")
        return render_page(request, "login.html", mfa_required=True, username=username)
    if result.get("locked_until"):
        add_flash(
            request,
            f"Compte temporairement bloqué jusqu'à {result['locked_until'].strftime('%H:%M:%S')}.",
            "danger",
        )
    else:
        for error in result.get("errors", []):
            add_flash(request, error, "danger")
    return render_page(request, "login.html", status_code=401)


@app.get("/dashboard", response_class=HTMLResponse, name="dashboard")
async def dashboard(request: Request) -> Response:
    user = await require_session(request)
    return render_page(request, "dashboard.html", user=user)


@app.get("/account/password", response_class=HTMLResponse, name="password_settings")
async def password_settings_page(request: Request) -> Response:
    await require_session(request)
    return render_page(request, "password_change.html")


@app.post("/account/password", response_class=HTMLResponse, name="password_settings_submit")
async def password_settings_submit(request: Request) -> Response:
    await require_session(request)
    form = await request.form()
    await require_csrf(request, form)
    current_password = str(form.get("current_password", ""))
    new_password = str(form.get("new_password", ""))
    password_confirm = str(form.get("password_confirm", ""))

    if not current_password or not new_password or not password_confirm:
        add_flash(request, "Tous les champs sont requis.", "danger")
    elif new_password != password_confirm:
        add_flash(request, "Les nouveaux mots de passe ne correspondent pas.", "danger")
    else:
        result = await run_in_threadpool(
            change_password,
            request.session["user_id"],
            current_password,
            new_password,
        )
        if result["success"]:
            request.session.clear()
            add_flash(
                request,
                "Mot de passe modifié. Connectez-vous avec votre nouveau mot de passe.",
                "success",
            )
            return redirect_to(request, "login")
        for error in result.get("errors", []):
            add_flash(request, error, "danger")
    return render_page(request, "password_change.html", status_code=400)


@app.get("/mfa/enroll", response_class=HTMLResponse, name="mfa_enroll")
async def mfa_enroll_page(request: Request) -> Response:
    await require_session(request)
    user_id = request.session.get("user_id")
    username = request.session.get("username")
    try:
        result = await run_in_threadpool(
            enroll_mfa,
            user_id,
            username,
            session_token=request.session.get("session_token"),
        )
        if not result["success"]:
            add_flash(request, "Erreur lors de l'enrôlement MFA.", "danger")
            return redirect_to(request, "dashboard")

        qr_uri = result["qr_code_uri"]
        qr_image = await run_in_threadpool(generate_qr_code, qr_uri)
        return render_page(
            request,
            "mfa_enroll.html",
            qr_uri=qr_uri,
            qr_image=base64.b64encode(qr_image).decode("ascii"),
            secret=result["secret"],
            recovery_codes=result["recovery_codes"],
        )
    except Exception:
        logger.exception("Erreur MFA")
        add_flash(request, "Erreur lors de l'enrôlement MFA.", "danger")
        return redirect_to(request, "dashboard")


@app.post("/mfa/enroll", response_class=HTMLResponse, name="mfa_enroll_submit")
async def mfa_enroll_submit(request: Request) -> Response:
    await require_session(request)
    form = await request.form()
    await require_csrf(request, form)
    totp_code = str(form.get("totp_code", "")).strip()
    if not totp_code:
        add_flash(request, "Veuillez entrer le code TOTP.", "danger")
    else:
        valid = await run_in_threadpool(
            validate_mfa_enrollment,
            request.session.get("user_id"),
            totp_code,
            session_token=request.session.get("session_token"),
        )
        if valid:
            add_flash(request, "MFA activé avec succès ! Votre compte est maintenant plus sécurisé.", "success")
            return redirect_to(request, "dashboard")
        add_flash(request, "Code TOTP invalide. Veuillez réessayer.", "danger")
    return redirect_to(request, "mfa_enroll")


@app.post("/logout", name="logout")
async def logout(request: Request) -> RedirectResponse:
    form = await request.form()
    await require_csrf(request, form)
    token = request.session.get("session_token")
    if token:
        await run_in_threadpool(logout_user, token)
    request.session.clear()
    add_flash(request, "Vous avez été déconnecté avec succès.", "info")
    return redirect_to(request, "index")


@app.post("/api/validate-password", name="api_validate_password")
async def api_validate_password(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except ValueError:
        return JSONResponse({"valid": False, "errors": ["Corps JSON invalide."]}, status_code=400)
    if not isinstance(data, dict):
        return JSONResponse({"valid": False, "errors": ["Objet JSON attendu."]}, status_code=400)
    password = str(data.get("password", ""))
    username = str(data.get("username", ""))
    result = await run_in_threadpool(validate_password, password, username)
    return JSONResponse({"valid": result["valid"], "errors": result["errors"]})


@app.get("/test", response_class=HTMLResponse, name="test")
async def test_page(request: Request) -> HTMLResponse:
    return render_page(request, "test.html")
