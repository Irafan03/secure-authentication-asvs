"""
test_password_validation.py — Tests de validation des mots de passe ASVS 5.0.0 V6
Tests sans dépendance à la base de données
"""

import pytest
from auth_register import validate_password


# =============================================================================
# Tests ASVS 6.2 - Validation des mots de passe
# =============================================================================

def test_6_2_1_password_min_12_chars():
    """ASVS 6.2.1: Mot de passe d'au moins 12 caractères accepté."""
    # 12 caractères exactement - utiliser un mot de passe unique non compromis
    result = validate_password("xK9mP2nQ7wRt")
    assert result["valid"], f"Un mot de passe de 12 caractères devrait être accepté. Erreurs: {result['errors']}"
    
    # 11 caractères refusé
    result = validate_password("xK9mP2nQ7wR")
    assert not result["valid"], "Un mot de passe de 11 caractères devrait être refusé"
    assert any("12 caractères" in err for err in result["errors"])


def test_6_2_1_password_64_chars():
    """ASVS 6.2.1: Mot de passe de 64 caractères accepté."""
    # Utiliser un mot de passe unique non compromis
    password_64 = "xK9mP2nQ7wRt" * 5 + "xK9m"  # 64 caractères
    result = validate_password(password_64)
    assert result["valid"], f"Un mot de passe de 64 caractères devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_1_password_128_chars():
    """ASVS 6.2.1: Mot de passe de 128 caractères accepté (limite max)."""
    # Utiliser un mot de passe unique non compromis
    password_128 = "xK9mP2nQ7wRt" * 10 + "xK9mP2nQ"  # 128 caractères
    result = validate_password(password_128)
    assert result["valid"], f"Un mot de passe de 128 caractères devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_2_password_max_128_chars():
    """ASVS 6.2.2: Mot de passe > 128 caractères refusé."""
    password_129 = "a" * 129
    result = validate_password(password_129)
    assert not result["valid"], "Un mot de passe de 129 caractères devrait être refusé"
    assert any("128 caractères" in err for err in result["errors"])


def test_6_2_5_no_composition_rules_lowercase_only():
    """ASVS 6.2.5: Pas de règles de composition - mot de passe sans majuscule accepté."""
    # Mot de passe sans majuscule (seulement minuscules) - utiliser un mot unique
    password_no_upper = "hjklzxcvbnmqwe"
    result = validate_password(password_no_upper)
    assert result["valid"], f"Un mot de passe sans majuscule devrait être accepté (pas de règles de composition). Erreurs: {result['errors']}"


def test_6_2_5_no_composition_rules_no_symbols():
    """ASVS 6.2.5: Pas de règles de composition - mot de passe sans symbole accepté."""
    # Mot de passe sans symbole (seulement lettres) - utiliser un mot unique
    password_no_symbol = "hjklzxcvbnmqwert"
    result = validate_password(password_no_symbol)
    assert result["valid"], f"Un mot de passe sans symbole devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_5_no_composition_rules_no_numbers():
    """ASVS 6.2.5: Pas de règles de composition - mot de passe sans chiffre accepté."""
    password_no_number = "hjklzxcvbnmqwerty"
    result = validate_password(password_no_number)
    assert result["valid"], f"Un mot de passe sans chiffre devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_5_no_composition_rules_no_uppercase():
    """ASVS 6.2.5: Pas de règles de composition - mot de passe sans majuscule accepté."""
    password_no_uppercase = "qzwxecrvtbynumiko"
    result = validate_password(password_no_uppercase)
    assert result["valid"], f"Un mot de passe sans majuscule devrait être accepté. Erreurs: {result['errors']}"


def test_6_2_3_password_not_truncated():
    """ASVS 6.2.3: Pas de troncature silencieuse - erreur explicite si trop long."""
    password_too_long = "a" * 200
    result = validate_password(password_too_long)
    assert not result["valid"], "Un mot de passe trop long devrait être refusé explicitement"
    assert len(result["errors"]) > 0, "Une erreur explicite devrait être retournée"


def test_6_2_3_password_not_same_as_username():
    """ASVS 6.2.3: Le mot de passe ne doit pas être identique au nom d'utilisateur."""
    username = "myusername123"
    result = validate_password(username, username)
    assert not result["valid"], "Le mot de passe ne devrait pas être identique au nom d'utilisateur"
    assert any("nom d'utilisateur" in err.lower() for err in result["errors"])


def test_password_valid_examples():
    """Test de mots de passe valides variés."""
    valid_passwords = [
        "hjklmnopqrstu",            # minuscules seulement, 13 caractères
        "HJKLMNOPQRSTUV",           # majuscules seulement, 14 caractères
        "476859201347",             # chiffres seulement, 12 caractères
        "xK9mP2nQ7wRt",             # mix de tous les types, 12 caractères
        "xK9mP2nQ7wRt" * 10 + "xK9mP2nQ",  # longueur max (128)
        "hjkl-mnop-qrst",           # avec tirets
        "uniquepassword2025xyz",    # alphanumérique unique
    ]
    
    for pwd in valid_passwords:
        result = validate_password(pwd)
        assert result["valid"], f"Le mot de passe '{pwd}' devrait être valide. Erreurs: {result['errors']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
