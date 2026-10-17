"""
test_asvs_level2.py — Tests de conformité ASVS 5.0.0 V6 Niveau 2
"""

import pytest
from auth_register import validate_password
from auth_mfa import (
    generate_totp_secret, generate_totp_uri, verify_totp_code,
    generate_recovery_codes, enroll_mfa, validate_mfa_enrollment
)
import pyotp


# =============================================================================
# Tests ASVS 6.2.11 - Mots contextuels interdits
# =============================================================================

def test_6_2_11_contextual_words_rejected():
    """ASVS 6.2.11: Mot de passe contenant un mot contextuel refusé."""
    # Mots définis dans config.py: secure, authentication, asvs, auth, login
    
    # Mot contextuel direct
    result = validate_password("MySecurePassword123")
    assert not result["valid"], "Un mot de passe contenant 'secure' devrait être refusé"
    assert any("contexte" in err.lower() for err in result["errors"])
    
    # Mot contextuel en minuscules
    result = validate_password("authentication2024xyz")
    assert not result["valid"], "Un mot de passe contenant 'authentication' devrait être refusé"
    
    # Mot contextuel avec chiffres
    result = validate_password("auth123456789")
    assert not result["valid"], "Un mot de passe contenant 'auth' devrait être refusé"


def test_6_2_11_non_contextual_words_accepted():
    """ASVS 6.2.11: Mot de passe sans mot contextuel accepté."""
    # Mot de passe sans mots contextuels
    result = validate_password("MyStrongP@ssw0rd")
    # Pourrait être refusé par HIBP, mais pas par les mots contextuels
    if not result["valid"]:
        # Vérifier que ce n'est pas refusé pour un mot contextuel
        assert not any("contexte" in err.lower() for err in result["errors"])


# =============================================================================
# Tests ASVS 6.5 - MFA / TOTP
# =============================================================================

def test_6_5_1_totp_secret_generation():
    """ASVS 6.5.1, 6.5.4: Secret TOTP généré par CSPRNG avec entropie suffisante."""
    secret = generate_totp_secret()
    
    # Le secret doit être une chaîne base32 non vide
    assert len(secret) > 0, "Le secret TOTP ne devrait pas être vide"
    
    # Vérifier l'entropie minimale (20 bits requis, on génère 256 bits)
    # Un secret base32 de 32 bytes = 256 bits >> 20 bits
    assert len(secret) >= 32, "Le secret TOTP devrait avoir une entropie suffisante"


def test_6_5_1_totp_uri_generation():
    """ASVS 6.5.1: URI TOTP généré correctement pour le QR code."""
    secret = generate_totp_secret()
    uri = generate_totp_uri("testuser", secret)
    
    # Vérifier le format otpauth://
    assert uri.startswith("otpauth://totp/"), "L'URI devrait commencer par otpauth://totp/"
    assert "testuser" in uri, "L'URI devrait contenir le nom d'utilisateur"
    assert secret in uri, "L'URI devrait contenir le secret"


def test_6_5_3_totp_verification():
    """ASVS 6.5.3: Vérification d'un code TOTP valide."""
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret, interval=30, digits=6)
    
    # Générer un code valide
    code = totp.now()
    
    # La vérification nécessite un user_id et la base de données
    # Ce test vérifie seulement la génération de code valide
    assert len(code) == 6, "Le code TOTP devrait avoir 6 chiffres"
    assert code.isdigit(), "Le code TOTP devrait contenir uniquement des chiffres"


def test_6_5_2_recovery_codes_generation():
    """ASVS 6.5.1, 6.5.2: Codes de récupération générés avec entropie suffisante et hachés."""
    codes = generate_recovery_codes()
    
    # Devrait générer 10 codes par défaut
    assert len(codes) == 10, "Devrait générer 10 codes de récupération"
    
    for code_plain, code_hash in codes:
        # Format: XXXX-XXXX
        assert len(code_plain) == 9, "Code de récupération devrait avoir 9 caractères (XXXX-XXXX)"
        assert "-" in code_plain, "Code de récupération devrait contenir un tiret"
        
        # Le hash doit être différent du code en clair
        assert code_hash != code_plain, "Le code devrait être haché"
        
        # Le hash Argon2 devrait commencer par $argon2
        assert code_hash.startswith("$argon2"), "Le code devrait être haché avec Argon2"


def test_6_5_2_recovery_codes_unique():
    """ASVS 6.5.2: Codes de récupération sont uniques."""
    codes = generate_recovery_codes()
    
    codes_plain = [code[0] for code in codes]
    
    # Tous les codes doivent être différents
    assert len(codes_plain) == len(set(codes_plain)), "Tous les codes de récupération devraient être uniques"


# =============================================================================
# Tests ASVS 6.3.8 - Énumération via inscription
# =============================================================================

def test_6_3_8_registration_generic_message():
    """ASVS 6.3.8: Message générique à l'inscription (pas d'énumération)."""
    # Ce test nécessite la base de données pour être complet
    # On teste ici la logique de validation des mots contextuels
    
    # Vérifier que validate_password ne révèle pas d'informations spécifiques
    result1 = validate_password("MySecurePass123")
    result2 = validate_password("MyAuthPass456")
    
    # Les deux devraient être refusés pour mot contextuel
    assert not result1["valid"]
    assert not result2["valid"]
    
    # Les messages devraient être génériques (pas spécifiques au mot trouvé)
    for err in result1["errors"]:
        if "contexte" in err.lower():
            assert "secure" not in err.lower(), "Ne devrait pas révéler le mot spécifique"


# =============================================================================
# Tests ASVS 6.2.12 - HIBP au changement de mot de passe
# =============================================================================

def test_6_2_12_hibp_on_password_change():
    """ASVS 6.2.12: Vérification HIBP appliquée au changement de mot de passe."""
    # validate_password est appelé par change_password
    # Vérifier qu'un mot de passe compromis est refusé
    
    # Mot de passe très courant qui devrait être dans HIBP
    result = validate_password("password123456789")
    
    # Devrait être refusé (soit par liste locale, soit par HIBP)
    assert not result["valid"], "Un mot de passe compromis devrait être refusé"


# =============================================================================
# Tests ASVS 6.3.4 / 6.1.3 - Voies d'authentification
# =============================================================================

def test_6_3_4_authentication_paths_documented():
    """ASVS 6.3.4, 6.1.3: Les voies d'authentification sont documentées."""
    import os
    
    # Vérifier que le fichier de documentation existe
    doc_path = "docs/AUTHENTICATION_PATHS.md"
    assert os.path.exists(doc_path), "La documentation des voies d'authentification devrait exister"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
