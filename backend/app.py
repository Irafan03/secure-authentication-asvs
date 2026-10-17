"""
app.py — Interface web Flask pour le système d'authentification ASVS
Application de démonstration et test
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import logging
from functools import wraps
from datetime import datetime
import os
from html import escape

# Import des modules d'authentification
from .auth_register import register_user, validate_password
from .auth_login import authenticate_user, logout_user, validate_session
from .auth_mfa import enroll_mfa, validate_mfa_enrollment, generate_qr_code, generate_totp_uri
from .database import init_db
from .models import get_db_session, User, init_db_orm
from .password_recovery import (request_password_reset, complete_password_reset,
                               request_mfa_recovery, complete_mfa_recovery)

# Configuration de l'application
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = False  # Mettre True en production avec HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Décorateur pour les routes protégées
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'session_token' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
            return redirect(url_for('login'))
        
        # Valider le token de session
        session_data = validate_session(session['session_token'])
        if not session_data:
            session.clear()
            flash('Votre session a expiré. Veuillez vous reconnecter.', 'warning')
            return redirect(url_for('login'))

        if session.get('enrollment_only') and request.endpoint not in ('mfa_enroll', 'logout'):
            return redirect(url_for('mfa_enroll'))
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        current = validate_session(session.get('session_token'))
        if not current or current.get('role') != 'admin':
            return jsonify({'error': 'Accès refusé'}), 403
        return f(*args, **kwargs)
    return decorated_function


# Route principale
@app.route('/')
def index():
    """Page d'accueil."""
    if 'session_token' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# Route d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Page d'inscription."""
    if request.method == 'POST':
        wants_json = request.is_json or request.accept_mimetypes.best == 'application/json'
        form_data = request.get_json(silent=True) if request.is_json else request.form
        if not isinstance(form_data, dict) and request.is_json:
            form_data = {}
        form_data = form_data or {}
        username = form_data.get('username', '').strip()
        email = form_data.get('email', '').strip()
        password = form_data.get('password', '')
        password_confirm = form_data.get('password_confirm', '')
        
        # Validation basique
        if not all([username, email, password, password_confirm]):
            if wants_json:
                return jsonify({'success': False, 'errors': ['Tous les champs sont requis.']}), 400
            flash('Tous les champs sont requis.', 'danger')
            return render_template('register.html')
        
        if password != password_confirm:
            if wants_json:
                return jsonify({'success': False, 'errors': ['Les mots de passe ne correspondent pas.']}), 400
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return render_template('register.html')
        
        # Tenter l'inscription
        result = register_user(username, email, password)
        
        if result['success']:
            if wants_json:
                return jsonify({'success': True, 'message': 'Compte créé. Vous pouvez maintenant vous connecter.'}), 201
            flash(f'Compte créé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        else:
            if wants_json:
                return jsonify({'success': False, 'errors': result['errors']}), 400
            for error in result['errors']:
                flash(error, 'danger')
    
    return render_template('register.html')


# Route de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion."""
    if request.method == 'POST':
        wants_json = request.is_json or request.accept_mimetypes.best == 'application/json'
        form_data = request.get_json(silent=True) if request.is_json else request.form
        if not isinstance(form_data, dict) and request.is_json:
            form_data = {}
        form_data = form_data or {}
        username = form_data.get('username', '').strip()
        password = form_data.get('password', '')
        totp_code = form_data.get('totp_code', '').strip()
        recovery_code = form_data.get('recovery_code', '')
        
        if not username or not password:
            if wants_json:
                return jsonify({'success': False, 'errors': ['Nom d\'utilisateur et mot de passe requis.']}), 400
            flash('Nom d\'utilisateur et mot de passe requis.', 'danger')
            return render_template('login.html')
        
        # Obtenir l'adresse IP du client
        ip_address = request.remote_addr
        
        # Tenter l'authentification
        result = authenticate_user(
            username=username,
            password=password,
            ip_address=ip_address,
            totp_code=totp_code if totp_code else None,
            recovery_code=recovery_code if recovery_code else None,
        )
        
        if result['success']:
            # Stocker le token de session
            session['session_token'] = result['session_token']
            session['username'] = result['user']['username']
            session['user_id'] = result['user']['id']
            if result.get('mfa_enrollment_required'):
                session['enrollment_only'] = True
                if wants_json:
                    return jsonify({'success': True, 'user': result['user'], 'mfa_enrollment_required': True}), 200
                flash('Réenrôlez votre facteur MFA pour terminer la connexion.', 'warning')
                return redirect(url_for('mfa_enroll'))
            if wants_json:
                return jsonify({'success': True, 'user': result['user']}), 200
            flash(f'Bienvenue, {result["user"]["username"]} !', 'success')
            return redirect(url_for('dashboard'))
        
        elif result.get('mfa_required'):
            if wants_json:
                return jsonify({'success': False, 'mfa_required': True, 'errors': result['errors']}), 200
            # MFA requis, afficher le champ TOTP
            session['pending_username'] = username
            session['pending_password'] = password  # En production, ne pas stocker !
            flash('Veuillez entrer votre code d\'authentification à deux facteurs.', 'info')
            return render_template('login.html', mfa_required=True, username=username)
        
        elif result.get('locked_until'):
            if wants_json:
                unlock_time = result['locked_until']
                return jsonify({
                    'success': False,
                    'errors': result['errors'],
                    'locked_until': unlock_time.isoformat() if hasattr(unlock_time, 'isoformat') else str(unlock_time),
                }), 423
            flash(f'Compte temporairement bloqué jusqu\'à {result["locked_until"].strftime("%H:%M:%S")}.', 'danger')
        else:
            if wants_json:
                return jsonify({'success': False, 'errors': result.get('errors', ['Identifiant ou mot de passe incorrect.'])}), 401
            for error in result['errors']:
                flash(error, 'danger')
    
    return render_template('login.html')


# Route du tableau de bord
@app.route('/dashboard')
@login_required
def dashboard():
    """Tableau de bord utilisateur."""
    session_data = validate_session(session['session_token'])
    return render_template('dashboard.html', user=session_data)


# Route d'enrôlement MFA
@app.route('/mfa/enroll', methods=['GET', 'POST'])
@login_required
def mfa_enroll():
    """Page d'enrôlement MFA."""
    user_id = session.get('user_id')
    username = session.get('username')
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        
        if not totp_code:
            flash('Veuillez entrer le code TOTP.', 'danger')
            return redirect(url_for('mfa_enroll'))
        
        # Valider l'enrôlement
        if validate_mfa_enrollment(user_id, totp_code):
            if session.pop('enrollment_only', False):
                session.clear()
                flash('Nouveau facteur MFA enregistré. Reconnectez-vous.', 'success')
                return redirect(url_for('login'))
            flash('MFA activé avec succès ! Votre compte est maintenant plus sécurisé.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Code TOTP invalide. Veuillez réessayer.', 'danger')
            return redirect(url_for('mfa_enroll'))
    
    # Générer le secret et le QR code
    try:
        result = enroll_mfa(user_id, username)
        
        if result['success']:
            # Stocker temporairement les codes de récupération dans la session
            session['recovery_codes'] = result['recovery_codes']
            
            # Générer l'URI pour le QR code
            qr_uri = result['qr_code_uri']
            
            return render_template('mfa_enroll.html', 
                                   qr_uri=qr_uri,
                                   secret=result['secret'],
                                   recovery_codes=result['recovery_codes'])
        else:
            flash('Erreur lors de l\'enrôlement MFA.', 'danger')
            return redirect(url_for('dashboard'))
    
    except Exception as e:
        logger.error(f"Erreur MFA: {e}")
        flash('Erreur lors de l\'enrôlement MFA.', 'danger')
        return redirect(url_for('dashboard'))


# Route de déconnexion
@app.route('/logout')
@login_required
def logout():
    """Déconnexion."""
    session_token = session.get('session_token')
    if session_token:
        logout_user(session_token)
    
    session.clear()
    flash('Vous avez été déconnecté avec succès.', 'info')
    return redirect(url_for('index'))


# Route API pour validation de mot de passe en temps réel
@app.route('/api/validate-password', methods=['POST'])
def api_validate_password():
    """API pour valider un mot de passe en temps réel."""
    data = request.get_json()
    password = data.get('password', '')
    username = data.get('username', '')
    
    result = validate_password(password, username)
    
    return jsonify({
        'valid': result['valid'],
        'errors': result['errors']
    })


@app.route('/password-reset', methods=['GET', 'POST'])
def password_reset_request():
    if request.method == 'GET':
        return app.response_class(
            '''<!doctype html><html lang="fr"><meta charset="utf-8"><title>Mot de passe oublié</title>
            <h1>Mot de passe oublié</h1><form method="post">
            <label>Nom d'utilisateur ou adresse e-mail <input name="identifier" required autocomplete="username"></label>
            <button type="submit">Envoyer les instructions</button></form></html>''', mimetype='text/html')
    data = request.get_json(silent=True) or request.form
    result = request_password_reset(data.get('identifier', ''), request.remote_addr or 'unknown')
    return jsonify(result), 200


@app.route('/password-reset/confirm', methods=['GET', 'POST'])
def password_reset_confirm():
    if request.method == 'GET':
        token = escape(request.args.get('token', ''), quote=True)
        response = app.response_class(
            f'''<!doctype html><html lang="fr"><meta charset="utf-8"><title>Réinitialiser le mot de passe</title>
            <h1>Réinitialiser le mot de passe</h1><form method="post">
            <input type="hidden" name="token" value="{token}">
            <label>Nouveau mot de passe <input type="password" name="new_password" required autocomplete="new-password"></label>
            <label>Code TOTP (si MFA activé) <input name="totp_code" inputmode="numeric" autocomplete="one-time-code"></label>
            <label>Code de récupération <input name="recovery_code" autocomplete="off"></label>
            <button type="submit">Confirmer</button></form></html>''', mimetype='text/html')
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response
    data = request.get_json(silent=True) or request.form
    result = complete_password_reset(
        data.get('token', ''), data.get('new_password', ''), request.remote_addr or 'unknown',
        data.get('totp_code'), data.get('recovery_code'))
    return jsonify(result), (200 if result.get('success') else 400)


@app.route('/admin/users/<int:user_id>/password-reset', methods=['POST'])
@admin_required
def admin_password_reset_request(user_id):
    result = request_password_reset('', request.remote_addr or 'unknown',
                                    initiated_by='admin', initiated_by_user_id=session.get('user_id'),
                                    target_user_id=user_id)
    # Admins address the target by ID; use the account's username only internally.
    return jsonify({'message': 'Si le compte existe, les instructions ont été envoyées.'}), 200


@app.route('/mfa/recovery/request', methods=['POST'])
@login_required
def mfa_recovery_request():
    ok = request_mfa_recovery(session.get('user_id'), request.remote_addr or 'unknown')
    return jsonify({'message': 'Si le compte peut être récupéré, les instructions ont été envoyées.'}), 200


@app.route('/mfa/recovery/confirm', methods=['GET', 'POST'])
@login_required
def mfa_recovery_confirm():
    if request.method == 'GET':
        token = escape(request.args.get('token', ''), quote=True)
        response = app.response_class(
            f'''<!doctype html><html lang="fr"><meta charset="utf-8"><title>Récupération MFA</title>
            <h1>Confirmer la récupération MFA</h1><form method="post">
            <input type="hidden" name="token" value="{token}">
            <label>Mot de passe actuel <input type="password" name="current_password" required autocomplete="current-password"></label>
            <button type="submit">Confirmer</button></form></html>''', mimetype='text/html')
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response
    data = request.get_json(silent=True) or request.form
    ok = complete_mfa_recovery(session.get('user_id'), data.get('token', ''),
                               data.get('current_password', ''), request.remote_addr or 'unknown')
    if ok:
        session.clear()
        return jsonify({'success': True, 'message': 'MFA réinitialisé. Reconnectez-vous puis enrôlez un nouveau facteur.'}), 200
    return jsonify({'success': False, 'message': 'Demande invalide ou expirée.'}), 400


# Route de test (à désactiver en production)
@app.route('/test')
def test():
    """Page de test pour vérifier l'installation."""
    return render_template('test.html')


# Gestionnaire d'erreur 404
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# Gestionnaire d'erreur 500
@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Erreur serveur: {e}")
    return render_template('500.html'), 500


# Initialisation de la base de données au démarrage
@app.before_request
def before_first_request():
    """Initialiser la BDD avant la première requête."""
    if not hasattr(app, 'db_initialized'):
        try:
            init_db()
            init_db_orm()
            app.db_initialized = True
            logger.info("Base de données initialisée")
        except Exception as e:
            logger.error(f"Erreur initialisation BDD: {e}")


if __name__ == '__main__':
    # En développement seulement
    app.run(debug=True, host='0.0.0.0', port=5000)
