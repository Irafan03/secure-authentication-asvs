"""
app.py — Interface web Flask pour le système d'authentification ASVS
Application de démonstration et test
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import logging
from functools import wraps
from datetime import datetime
import os

# Import des modules d'authentification
from auth_register import register_user, validate_password
from auth_login import authenticate_user, logout_user, validate_session
from auth_mfa import enroll_mfa, validate_mfa_enrollment, generate_qr_code, generate_totp_uri
from database import init_db

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
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        
        # Validation basique
        if not all([username, email, password, password_confirm]):
            flash('Tous les champs sont requis.', 'danger')
            return render_template('register.html')
        
        if password != password_confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return render_template('register.html')
        
        # Tenter l'inscription
        result = register_user(username, email, password)
        
        if result['success']:
            flash(f'Compte créé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        else:
            for error in result['errors']:
                flash(error, 'danger')
    
    return render_template('register.html')


# Route de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis.', 'danger')
            return render_template('login.html')
        
        # Obtenir l'adresse IP du client
        ip_address = request.remote_addr
        
        # Tenter l'authentification
        result = authenticate_user(
            username=username,
            password=password,
            ip_address=ip_address,
            totp_code=totp_code if totp_code else None
        )
        
        if result['success']:
            # Stocker le token de session
            session['session_token'] = result['session_token']
            session['username'] = result['user']['username']
            session['user_id'] = result['user']['id']
            flash(f'Bienvenue, {result["user"]["username"]} !', 'success')
            return redirect(url_for('dashboard'))
        
        elif result.get('mfa_required'):
            # MFA requis, afficher le champ TOTP
            session['pending_username'] = username
            session['pending_password'] = password  # En production, ne pas stocker !
            flash('Veuillez entrer votre code d\'authentification à deux facteurs.', 'info')
            return render_template('login.html', mfa_required=True, username=username)
        
        elif result.get('locked_until'):
            flash(f'Compte temporairement bloqué jusqu\'à {result["locked_until"].strftime("%H:%M:%S")}.', 'danger')
        else:
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
            app.db_initialized = True
            logger.info("Base de données initialisée")
        except Exception as e:
            logger.error(f"Erreur initialisation BDD: {e}")


if __name__ == '__main__':
    # En développement seulement
    app.run(debug=True, host='0.0.0.0', port=5000)
