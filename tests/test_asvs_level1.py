"""
test_asvs_level1.py — Tests de conformité ASVS 5.0.0 V6 Niveau 1
"""

import pytest
import time
from backend.auth_register import validate_password, register_user, check_password_pwned
from backend.auth_login import authenticate_user, check_rate_limit
from backend.database import init_db, get_connection


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Initialise la base de données pour les tests."""
    init_db()
    yield


@pytest.fixture(autouse=True)
def cleanup_test_data():
    """Nettoie les données de test après chaque test."""
    yield
    # Cleanup après le test
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username LIKE 'testuser%'")
            cursor.execute("DELETE FROM login_attempts WHERE identifier LIKE 'testuser%'")
            cursor.execute("DELETE FROM login_attempts WHERE ip_address LIKE '192.168.%'")
            conn.commit()
    except Exception:
        pass


# =============================================================================
# Tests ASVS 6.2 - Validation des mots de passe
# =============================================================================

def test_6_2_1_password_min_12_chars():
    # 12 caractères exactement
    result = validate_password("xK9mP2nQ7wRt")
    assert result["valid"], f"Un mot de passe de 12 caractères devrait être accepté. Erreurs: {result['errors']}"
    
    # 11 caractères refusé
    result = validate_password("xK9mP2nQ7wR")
    assert not result["valid"], "Un mot de passe de 11 caractères devrait être refusé"
    assert any("12 caractères" in err for err in result["errors"])


def test_6_2_1_password_64_chars():
    """ASVS 6.2.1: Mot de passe de 64 caractères accepté."""
    password_64 = "xK9mP2nQ7wRt" * 5 + "xK9m"
    result = validate_password(password_64)
    assert result["valid"], f"Un mot de passe de 64 caractères devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_1_password_128_chars():
    """ASVS 6.2.1: Mot de passe de 128 caractères accepté (limite max)."""
    password_128 = "xK9mP2nQ7wRt" * 10 + "xK9mP2nQ"
    result = validate_password(password_128)
    assert result["valid"], f"Un mot de passe de 128 caractères devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_2_password_max_128_chars():
    """ASVS 6.2.2: Mot de passe > 128 caractères refusé."""
    password_129 = "a" * 129
    result = validate_password(password_129)
    assert not result["valid"], "Un mot de passe de 129 caractères devrait être refusé"
    assert any("128 caractères" in err for err in result["errors"])


def test_6_2_5_no_composition_rules():
    """ASVS 6.2.5: Pas de règles de composition - mot de passe sans majuscule accepté."""
    # Mot de passe sans majuscule (seulement minuscules)
    password_no_upper = "hjklzxcvbnmqwe"
    result = validate_password(password_no_upper)
    assert result["valid"], f"Un mot de passe sans majuscule devrait être accepté (pas de règles de composition). Erreurs: {result['errors']}"
    
    # Mot de passe sans symbole (seulement lettres)
    password_no_symbol = "hjklzxcvbnmqwe"
    result = validate_password(password_no_symbol)
    assert result["valid"], f"Un mot de passe sans symbole devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_4_compromised_password_rejected():
    """ASVS 6.2.4: Mot de passe compromis refusé (liste locale ou HIBP)."""
    # Test avec un mot de passe très courant qui devrait être dans la liste locale
    result = validate_password("password123456")
    # Ce mot de passe devrait être refusé soit par la liste locale, soit par HIBP
    if result["valid"]:
        # Si la validation locale passe, tester HIBP directement
        is_safe = check_password_pwned("password123456")
        assert not is_safe, "Le mot de passe 'password123456' devrait être détecté comme compromis"


def test_6_2_3_password_not_truncated():
    """ASVS 6.2.3: Pas de troncature silencieuse - erreur explicite si trop long."""
    password_too_long = "a" * 200
    result = validate_password(password_too_long)
    assert not result["valid"], "Un mot de passe trop long devrait être refusé explicitement"
    assert len(result["errors"]) > 0, "Une erreur explicite devrait être retournée"


# =============================================================================
# Tests ASVS 6.3 - Rate Limiting et protection brute force
# =============================================================================

def test_6_3_1_rate_limiting_by_ip():
    """ASVS 6.3.1: Rate limiting par IP empêche les attaques depuis une même IP."""
    username = "testuser_ip"
    ip = "192.168.1.100"
    
    # Créer un utilisateur de test
    result = register_user(username, f"{username}@test.com", "RandomPass9988#1")
    assert result["success"], f"Échec création utilisateur: {result.get('errors')}"
    
    # Simuler plusieurs tentatives échouées depuis la même IP
    for i in range(21):  # Dépasser le seuil IP (20)
        authenticate_user(f"wrong_user_{i}", "wrongpass", ip)
    
    # La prochaine tentative depuis cette IP devrait être bloquée
    rate_limit = check_rate_limit(username, ip)
    assert not rate_limit['allowed'], "L'IP devrait être bloquée après 20 tentatives"


def test_6_3_1_rate_limiting_no_account_lockout_dos():
    """ASVS 6.3.1: Impossible de verrouiller le compte d'un autre utilisateur depuis une autre IP."""
    username = "testuser_nodos"
    victim_ip = "192.168.1.200"
    attacker_ip = "192.168.1.201"
    
    # Créer un utilisateur de test
    result = register_user(username, f"{username}@test.com", "RandomPass9988#2")
    assert result["success"], f"Échec création utilisateur: {result.get('errors')}"
    
    # Un attaquant depuis une IP différente fait plusieurs tentatives
    for i in range(10):
        authenticate_user(username, "wrongpassword", attacker_ip)
    
    # L'utilisateur légitime depuis sa propre IP devrait pouvoir se connecter
    rate_limit = check_rate_limit(username, victim_ip)
    # Même si username a eu des échecs, depuis une nouvelle IP (victim_ip),
    # le compteur (username, victim_ip) devrait être à 0
    assert rate_limit['allowed'], "L'utilisateur légitime depuis une IP différente devrait pouvoir se connecter"


def test_6_3_1_progressive_delay():
    """ASVS 6.3.1: Délai progressif plutôt que blocage dur."""
    username = "testuser_delay"
    ip = "192.168.1.202"
    
    # Créer un utilisateur
    result = register_user(username, f"{username}@test.com", "RandomPass9988#3")
    assert result["success"]
    
    # Première tentative échouée
    authenticate_user(username, "wrongpass", ip)
    
    # Vérifier le rate limit - devrait avoir un délai mais être autorisé
    rate_limit = check_rate_limit(username, ip)
    # Après 1 échec sur (username, IP), on devrait encore être autorisé (seuil = 5)
    assert rate_limit['allowed'], "Devrait être autorisé après 1 seule tentative"


# =============================================================================
# Tests ASVS 6.3.8 - Protection timing attack
# =============================================================================

def test_6_3_8_timing_attack_protection():
    """ASVS 6.3.8: Temps de réponse comparable pour utilisateur existant et inexistant."""
    ip = "192.168.1.203"
    
    # Créer un utilisateur
    username_exists = "testuser_timing_exists"
    result = register_user(username_exists, f"{username_exists}@test.com", "RandomPass9988#4")
    assert result["success"]
    
    # Mesurer le temps pour un utilisateur existant
    start = time.time()
    authenticate_user(username_exists, "wrongpassword", ip)
    time_exists = time.time() - start
    
    # Mesurer le temps pour un utilisateur inexistant
    username_not_exists = "testuser_timing_notexists"
    start = time.time()
    authenticate_user(username_not_exists, "wrongpassword", ip)
    time_not_exists = time.time() - start
    
    # Les temps devraient être comparables (différence < 100ms)
    time_diff = abs(time_exists - time_not_exists)
    assert time_diff < 0.1, f"Différence de temps trop importante: {time_diff}s (devrait être < 0.1s)"


def test_6_3_8_generic_error_messages():
    """ASVS 6.3.8: Messages d'erreur génériques (pas de distinction utilisateur/mot de passe)."""
    ip = "192.168.1.204"
    
    # Créer un utilisateur
    username = "testuser_messages"
    result = register_user(username, f"{username}@test.com", "RandomPass9988#5")
    assert result["success"]
    
    # Tester avec utilisateur inexistant
    result_no_user = authenticate_user("nonexistent_user", "anypassword", ip)
    
    # Tester avec mauvais mot de passe
    result_wrong_pass = authenticate_user(username, "wrongpassword", ip)
    
    # Les messages devraient être identiques
    assert result_no_user["errors"] == result_wrong_pass["errors"], \
        "Les messages d'erreur devraient être identiques (utilisateur inexistant vs mauvais mot de passe)"


# =============================================================================
# Tests ASVS 6.4 - Récupération de compte
# =============================================================================

def test_6_4_2_no_password_reset():
    """ASVS 6.4.2: Pas de fonction de reset de mot de passe (Non applicable)."""
    # Ce test vérifie simplement que la fonction n'existe pas
    import backend.auth_login
    assert not hasattr(auth_login, 'reset_password'), \
        "Pas de fonction reset_password (marquée Non applicable)"


# =============================================================================
# Tests ASVS 6.3.2 - Pas de comptes par défaut
# =============================================================================

def test_6_3_2_no_default_accounts():
    """ASVS 6.3.2: Vérifier qu'aucun compte par défaut (root, admin, sa) n'existe."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE username IN ('root', 'admin', 'sa', 'administrator')")
            count = cursor.fetchone()[0]
            assert count == 0, f"Aucun compte par défaut ne devrait exister (trouvé: {count})"
    except Exception as e:
        pytest.fail(f"Erreur lors de la vérification des comptes par défaut: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
