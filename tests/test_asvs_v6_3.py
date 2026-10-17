"""
test_asvs_v6_3.py — Suite de tests automatisés pour ASVS 5.0.0 V6.3 (6.3.1 à 6.3.8)
Niveau L2 avec exigences L3 (notifications et anti-énumération)
"""

import time
import pytest
from datetime import datetime, timedelta
import pyotp

from backend.database import init_db, get_connection
from backend.models import get_db_session, User, LoginAttempt, UserDevice, MfaSecret, MfaRecoveryCode
from backend.notifications import (
    BaseNotificationService, DevLogNotificationService,
    get_notification_service, set_notification_service
)
from backend.auth_register import (
    register_user, change_password, change_email, change_username,
    validate_password
)
from backend.auth_login import (
    authenticate_user, check_rate_limit, record_login_attempt,
    _get_dummy_hash
)
from backend.auth_mfa import (
    generate_totp_secret, enroll_mfa, validate_mfa_enrollment,
    verify_totp_code, verify_recovery_code, is_mfa_enabled
)
from backend.create_admin import create_admin
from backend.config import (
    RATE_LIMIT_LOCKOUT_MESSAGE, INVALID_CREDENTIALS_MESSAGE,
    LOGIN_INACTIVITY_THRESHOLD, SUSPICIOUS_FAILED_ATTEMPTS_THRESHOLD
)


class MockTestNotificationService(DevLogNotificationService):
    """Service de notification en mémoire dédié aux assertions de tests."""
    def __init__(self):
        super().__init__()
        self.events = []

    def send_notification(self, recipient: str, subject: str, message: str, event_type: str) -> bool:
        self.events.append({
            "recipient": recipient,
            "subject": subject,
            "message": message,
            "event_type": event_type,
            "time": datetime.now()
        })
        return super().send_notification(recipient, subject, message, event_type)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()
    yield


@pytest.fixture(autouse=True)
def clean_and_mock_notifs():
    mock_notif = MockTestNotificationService()
    set_notification_service(mock_notif)
    
    # Nettoyage des tables de test
    sess = get_db_session()
    try:
        sess.query(LoginAttempt).filter(LoginAttempt.identifier.like("v63_%")).delete(synchronize_session=False)
        sess.query(LoginAttempt).filter(LoginAttempt.ip_address.like("10.0.%")).delete(synchronize_session=False)
        users = sess.query(User).filter(User.username.like("v63_%")).all()
        for u in users:
            sess.delete(u)
        sess.commit()
    except Exception:
        sess.rollback()
    finally:
        sess.close()

    yield mock_notif

    # Nettoyage après test
    sess = get_db_session()
    try:
        sess.query(LoginAttempt).filter(LoginAttempt.identifier.like("v63_%")).delete(synchronize_session=False)
        sess.query(LoginAttempt).filter(LoginAttempt.ip_address.like("10.0.%")).delete(synchronize_session=False)
        users = sess.query(User).filter(User.username.like("v63_%")).all()
        for u in users:
            sess.delete(u)
        sess.commit()
    except Exception:
        sess.rollback()
    finally:
        sess.close()


# =============================================================================
# 6.3.1 : Bourrage d'identifiants et force brute
# =============================================================================

def test_6_3_1_no_account_lockout_dos_from_different_ip():
    """Un attaquant ne peut pas verrouiller le compte d'un utilisateur légitime depuis une autre IP."""
    username = "v63_user_victim"
    victim_ip = "10.0.1.50"
    attacker_ip = "10.0.1.99"
    password = "VictimStrongPass123!"

    reg = register_user(username, f"{username}@test.com", password)
    assert reg["success"]

    # L'attaquant effectue 6 échecs consécutifs depuis son IP
    for _ in range(6):
        auth = authenticate_user(username, "BadAttackerPass123!", attacker_ip)
        assert not auth["success"]

    # Le couple (username, attacker_ip) est bloqué
    limit_attacker = check_rate_limit(username, attacker_ip)
    assert not limit_attacker["allowed"]

    # Mais l'utilisateur légitime depuis son IP victim_ip N'EST PAS BLOQUÉ
    limit_victim = check_rate_limit(username, victim_ip)
    assert limit_victim["allowed"]
    auth_victim = authenticate_user(username, password, victim_ip)
    assert auth_victim["success"]


def test_6_3_1_progressive_delay_on_failures():
    """Le ralentissement (délai progressif) s'applique après N échecs sur le username."""
    username = "v63_user_delay"
    ip = "10.0.1.51"
    password = "DelayPass12345!"

    reg = register_user(username, f"{username}@test.com", password)
    assert reg["success"]

    # 1 échec -> délai calculé > 0
    authenticate_user(username, "WrongPass1!", ip)
    res = check_rate_limit(username, ip)
    assert res["allowed"]
    assert res["delay"] > 0

    # 3 échecs -> délai encore plus grand
    authenticate_user(username, "WrongPass2!", ip)
    authenticate_user(username, "WrongPass3!", ip)
    res2 = check_rate_limit(username, ip)
    assert res2["delay"] > res["delay"]


def test_6_3_1_only_failures_counted_for_lockout():
    """Seuls les échecs comptent dans les compteurs de verrouillage."""
    username = "v63_user_succ"
    ip = "10.0.1.52"
    password = "SuccessPass123!"

    reg = register_user(username, f"{username}@test.com", password)
    assert reg["success"]

    # 10 connexions réussies consécutives
    for _ in range(10):
        auth = authenticate_user(username, password, ip)
        assert auth["success"]

    # Le rate limit reste 100% autorisé
    limit = check_rate_limit(username, ip)
    assert limit["allowed"]
    assert limit["delay"] == 0


def test_6_3_1_uniform_lockout_message():
    """Le message de limitation est identique que le compte existe ou non."""
    ip = "10.0.1.53"
    # Bloquer l'IP en effectuant 21 échecs
    for i in range(21):
        authenticate_user(f"v63_nonexist_{i}", "WrongPass123!", ip)

    res_exist = authenticate_user("v63_any_user", "WrongPass123!", ip)
    res_nonexist = authenticate_user("v63_random_ghost", "WrongPass123!", ip)

    assert not res_exist["success"]
    assert not res_nonexist["success"]
    assert res_exist["errors"] == res_nonexist["errors"]
    assert RATE_LIMIT_LOCKOUT_MESSAGE in res_exist["errors"][0]


# =============================================================================
# 6.3.2 : Comptes par défaut
# =============================================================================

def test_6_3_2_no_default_accounts():
    """Aucun compte par défaut n'existe après initialisation de la base."""
    sess = get_db_session()
    try:
        count = sess.query(User).filter(User.username.in_(['root', 'admin', 'administrator', 'sa', 'guest', 'test'])).count()
        assert count == 0, f"Des comptes par défaut ont été trouvés : {count}"
    finally:
        sess.close()


def test_6_3_2_create_admin_cli_requires_strong_password():
    """La commande d'installation dédiée crée un administrateur avec mot de passe conforme."""
    admin_user = "v63_admin_ops"
    admin_email = "v63_admin@ops-admin.com"

    # Refus si mot de passe trop faible
    created_weak = create_admin(admin_user, admin_email, "weak")
    assert not created_weak

    # Succès avec mot de passe robuste ASVS 6.2
    strong_pass = "AdminSuperSecret2026!#"
    created_ok = create_admin(admin_user, admin_email, strong_pass)
    assert created_ok

    # Vérifier que le compte a bien le rôle admin
    sess = get_db_session()
    try:
        u = sess.query(User).filter(User.username == admin_user).first()
        assert u is not None
        assert u.role == 'admin'
    finally:
        sess.close()


# =============================================================================
# 6.3.3 : Authentification multifacteur (TOTP)
# =============================================================================

def test_6_3_3_cannot_login_without_mfa():
    """Connexion impossible sans second facteur lorsque le MFA est activé."""
    username = "v63_mfa_user"
    email = f"{username}@test.com"
    password = "MfaStrongPass123!"
    reg = register_user(username, email, password)
    assert reg["success"]
    user_id = reg["user_id"]
    # Enrôler et valider le MFA
    enroll = enroll_mfa(user_id, username)
    secret = enroll["secret"]
    first_code = pyotp.TOTP(secret).now()
    val = validate_mfa_enrollment(user_id, first_code)
    assert val
    assert is_mfa_enabled(user_id)
    
    # 1. Connexion avec seulement le mot de passe -> MFA requis, pas de session
    auth_no_code = authenticate_user(username, password, "10.0.1.60")
    assert not auth_no_code["success"]
    assert auth_no_code.get("mfa_required") is True
    assert "session_token" not in auth_no_code

    # 2. Connexion avec mot de passe + code TOTP valide -> Succès
    valid_code = pyotp.TOTP(secret).now()
    auth_with_code = authenticate_user(username, password, "10.0.1.60", totp_code=valid_code)
    assert auth_with_code["success"]
    assert "session_token" in auth_with_code


def test_6_3_3_totp_replay_rejected():
    """Rejeu d'un code TOTP refusé dans la même fenêtre."""
    username = "v63_mfa_replay"
    email = f"{username}@test.com"
    password = "ReplayPass123!"

    reg = register_user(username, email, password)
    user_id = reg["user_id"]

    enroll = enroll_mfa(user_id, username)
    secret = enroll["secret"]
    first_code = pyotp.TOTP(secret).now()
    validate_mfa_enrollment(user_id, first_code)

    code = pyotp.TOTP(secret).now()
    # Première utilisation -> valide
    assert verify_totp_code(secret, code, user_id) is True

    # Rejeu immédiat du même code -> REJETÉ
    assert verify_totp_code(secret, code, user_id) is False


def test_6_3_3_recovery_code_single_use():
    """Code de récupération utilisable une seule fois."""
    username = "v63_mfa_recovery"
    email = f"{username}@test.com"
    password = "RecoveryPass123!"

    reg = register_user(username, email, password)
    user_id = reg["user_id"]

    enroll = enroll_mfa(user_id, username)
    secret = enroll["secret"]
    recovery_codes = enroll["recovery_codes"]
    first_code = pyotp.TOTP(secret).now()
    validate_mfa_enrollment(user_id, first_code)

    single_code = recovery_codes[0]

    # Première utilisation avec code de secours -> succès
    auth1 = authenticate_user(username, password, "10.0.1.61", recovery_code=single_code)
    assert auth1["success"]

    # Deuxième utilisation du même code -> refusée
    auth2 = authenticate_user(username, password, "10.0.1.61", recovery_code=single_code)
    assert not auth2["success"]
    assert "Code d'authentification invalide" in auth2["errors"]


# =============================================================================
# 6.3.4 : Voies d'authentification protégées
# =============================================================================

def test_6_3_4_no_bypass_and_password_change_rate_limited():
    """Aucune voie d'authentification ne contourne le MFA ni le rate limiting."""
    username = "v63_user_paths"
    email = f"{username}@test.com"
    password = "ValidCurrentPassword123!"

    reg = register_user(username, email, password)
    user_id = reg["user_id"]
    ip = "10.0.1.70"

    # La voie change_password applique le rate limiting après 5 échecs sur (username, IP)
    for _ in range(5):
        res = change_password(user_id, "BadCurrent123!", "NewValidPass456!", ip)
        assert not res["success"]

    # La 6ème tentative doit être bloquée par le rate limit
    res_blocked = change_password(user_id, password, "NewValidPass456!", ip)
    assert not res_blocked["success"]
    assert any("Trop de tentatives" in err for err in res_blocked["errors"])


# =============================================================================
# 6.3.5 : Notification des tentatives suspectes
# =============================================================================

def test_6_3_5_suspicious_notifications(clean_and_mock_notifs):
    """Une notification est déclenchée pour chaque cas suspect."""
    mock_service = clean_and_mock_notifs
    username = "v63_user_suspect"
    email = f"{username}@test.com"
    password = "SuspectPass123!"

    reg = register_user(username, email, password)
    user_id = reg["user_id"]

    # 1. Connexion depuis un nouvel appareil ou une nouvelle IP -> Notification new device
    auth_new_dev = authenticate_user(username, password, "10.0.1.80", user_agent="Firefox/Linux")
    assert auth_new_dev["success"]
    types = [e["event_type"] for e in mock_service.events]
    assert "suspicious_new_device" in types

    mock_service.events.clear()

    # 2. Authentification partiellement réussie (mot de passe correct mais MFA échoué)
    enroll = enroll_mfa(user_id, username)
    secret = enroll["secret"]
    first_code = pyotp.TOTP(secret).now()
    validate_mfa_enrollment(user_id, first_code)

    auth_partial = authenticate_user(username, password, "10.0.1.80", totp_code="000000")
    assert not auth_partial["success"]
    types = [e["event_type"] for e in mock_service.events]
    assert "partial_auth_failure" in types

    mock_service.events.clear()

    # 3. Connexion réussie après plusieurs échecs consécutifs
    valid_totp = pyotp.TOTP(secret).now()
    for _ in range(3):
        authenticate_user(username, "BadPass!", "10.0.1.81", totp_code=valid_totp)

    auth_after_fails = authenticate_user(username, password, "10.0.1.81", totp_code=valid_totp)
    assert auth_after_fails["success"]
    types = [e["event_type"] for e in mock_service.events]
    assert "login_after_failures" in types

    mock_service.events.clear()

    # 4. Connexion après une longue inactivité
    sess = get_db_session()
    try:
        u = sess.query(User).filter(User.id == user_id).first()
        u.last_login_at = datetime.now() - timedelta(days=45)
        sess.commit()
    finally:
        sess.close()

    recovery_code = enroll["recovery_codes"][0]
    auth_inactive = authenticate_user(username, password, "10.0.1.80", recovery_code=recovery_code)
    assert auth_inactive["success"]
    types = [e["event_type"] for e in mock_service.events]
    assert "inactive_login" in types

    # Vérification qu'aucun mot de passe ni secret n'est contenu dans les messages
    for event in mock_service.events:
        assert password not in event["message"]
        assert secret not in event["message"]


# =============================================================================
# 6.3.6 : Email non utilisé comme facteur d'authentification
# =============================================================================

def test_6_3_6_no_email_authentication_factor():
    """Aucune route ni fonction n'authentifie par code ou lien envoyé par email."""
    import backend.auth_login
    import backend.auth_mfa

    # Vérifier l'absence de toute fonction d'envoi de lien de connexion ou OTP par email
    forbidden_terms = ["magic_link", "email_otp", "send_login_email", "verify_email_code"]
    for term in forbidden_terms:
        assert not hasattr(auth_login, term), f"{term} ne devrait pas exister dans auth_login"
        assert not hasattr(auth_mfa, term), f"{term} ne devrait pas exister dans auth_mfa"


# =============================================================================
# 6.3.7 : Notification après mise à jour des identifiants
# =============================================================================

def test_6_3_7_credential_update_notifications(clean_and_mock_notifs):
    """Une notification est déclenchée après modification d'identifiant et envoyée à l'ancienne et nouvelle adresse."""
    mock_service = clean_and_mock_notifs
    username = "v63_user_update"
    old_email = "v63_user_old@test.com"
    new_email = "v63_user_new@test.com"
    current_pass = "CurrentPass12345!"
    new_pass = "BrandNewPass67890!"

    reg = register_user(username, old_email, current_pass)
    assert reg["success"]
    user_id = reg["user_id"]

    mock_service.events.clear()

    # 1. Notification changement de mot de passe
    pw_res = change_password(user_id, current_pass, new_pass, "10.0.1.90")
    assert pw_res["success"]
    types = [e["event_type"] for e in mock_service.events]
    assert "password_changed" in types
    assert new_pass not in mock_service.events[-1]["message"]

    mock_service.events.clear()

    # 2. Notification changement d'email (envoyée à l'ancienne ET à la nouvelle adresse)
    em_res = change_email(user_id, new_email, new_pass, "10.0.1.90")
    assert em_res["success"]
    recipients = [e["recipient"] for e in mock_service.events]
    assert old_email in recipients
    assert new_email in recipients

    mock_service.events.clear()

    # 3. Notification changement de username
    un_res = change_username(user_id, "v63_new_name", new_pass, "10.0.1.90")
    assert un_res["success"]
    types = [e["event_type"] for e in mock_service.events]
    assert "username_changed" in types


# =============================================================================
# 6.3.8 : Pas d'énumération d'utilisateurs
# =============================================================================

def test_6_3_8_anti_enumeration_login():
    """Messages et codes HTTP/résultats identiques pour utilisateur existant et inexistant."""
    username = "v63_user_enum"
    email = f"{username}@test.com"
    password = "EnumPassword123!"

    reg = register_user(username, email, password)
    assert reg["success"]

    ip = "10.0.1.95"
    res_wrong_pw = authenticate_user(username, "BadPassword999!", ip)
    res_nonexist = authenticate_user("v63_nonexistent_user", "BadPassword999!", ip)

    assert not res_wrong_pw["success"]
    assert not res_nonexist["success"]
    assert res_wrong_pw["errors"] == res_nonexist["errors"]
    assert res_wrong_pw["errors"] == [INVALID_CREDENTIALS_MESSAGE]


def test_6_3_8_timing_attack_response_comparable():
    """Temps de réponse comparables entre utilisateur existant et inexistant (écart sous seuil raisonnable sur plusieurs mesures)."""
    diffs = []
    for i in range(3):
        u_exist = f"v63_timing_usr_{i}"
        u_ghost = f"v63_ghost_usr_{i}"
        register_user(u_exist, f"{u_exist}@test.com", "TimingPass12345!")
        ip = f"10.0.9.{i}"

        t0 = time.perf_counter()
        authenticate_user(u_exist, "WrongGuess123!", ip)
        dur_exist = time.perf_counter() - t0

        t1 = time.perf_counter()
        authenticate_user(u_ghost, "WrongGuess123!", ip)
        dur_ghost = time.perf_counter() - t1

        diffs.append(abs(dur_exist - dur_ghost))

    avg_diff = sum(diffs) / len(diffs)
    # Les deux voies exécutent une vérification Argon2id, l'écart moyen doit être sous 150ms
    assert avg_diff < 0.15, f"Écart moyen de timing trop grand : {avg_diff:.3f}s"


def test_6_3_8_registration_response_generic():
    """Réponse d'inscription identique que le nom ou l'email existe déjà."""
    username = "v63_reg_duplicate"
    email = f"{username}@test.com"
    password = "RegPassDuplicate123!"

    reg1 = register_user(username, email, password)
    assert reg1["success"]

    # Tentative avec le même username
    reg_dup_user = register_user(username, "different_email@test.com", password)
    # Tentative avec le même email
    reg_dup_email = register_user("different_user", email, password)

    assert not reg_dup_user["success"]
    assert not reg_dup_email["success"]
    # Messages d'erreur génériques identiques
    assert reg_dup_user["errors"] == reg_dup_email["errors"]
    assert "Ce nom d'utilisateur ou cette adresse email est déjà utilisé" in reg_dup_user["errors"][0]
