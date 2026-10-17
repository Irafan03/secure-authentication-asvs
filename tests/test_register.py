"""
test_register.py — Tests pour l'inscription sécurisée
ASVS v4.0 — Niveau 2
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_register import (
    validate_username, validate_email_address, validate_password,
    hash_password, verify_password, register_user, change_password,
    load_common_passwords, PasswordValidationError, RegistrationError
)

class TestUsernameValidation:
    """Tests de validation du nom d'utilisateur."""
    
    def test_valid_usernames(self):
        """Test avec des noms d'utilisateur valides."""
        valid_usernames = [
            "john_doe", "user123", "test-user", "alice",
            "bob_smith", "user2024", "admin-dev"
        ]
        
        for username in valid_usernames:
            result = validate_username(username)
            assert result["valid"] is True, f"'{username}' devrait être valide"
            assert len(result["errors"]) == 0
    
    def test_invalid_usernames(self):
        """Test avec des noms d'utilisateur invalides."""
        invalid_cases = [
            ("", "Nom d'utilisateur vide"),
            ("ab", "Trop court"),
            ("a" * 65, "Trop long"),
            ("user@name", "Caractères invalides"),
            ("user name", "Espaces non autorisés"),
            ("_username", "Commence par underscore"),
            ("username_", "Finit par underscore"),
            ("-username", "Commence par tiret"),
            ("username-", "Finit par tiret"),
            ("user$name", "Caractères spéciaux"),
            ("123", "Trop court même avec chiffres")
        ]
        
        for username, description in invalid_cases:
            result = validate_username(username)
            assert result["valid"] is False, f"'{username}' ne devrait pas être valide ({description})"
            assert len(result["errors"]) > 0

class TestEmailValidation:
    """Tests de validation d'email."""
    
    def test_valid_emails(self):
        """Test avec des emails valides."""
        valid_emails = [
            "user@example.com", "test.email@domain.org",
            "john.doe+tag@company.co.uk", "admin@localhost.dev"
        ]
        
        for email in valid_emails:
            result = validate_email_address(email)
            assert result["valid"] is True, f"'{email}' devrait être valide"
            assert "normalized" in result
    
    def test_invalid_emails(self):
        """Test avec des emails invalides."""
        invalid_emails = [
            "", "email", "email@", "@domain.com",
            "email@domain", "email..double@domain.com",
            "email@domain..com", "email with spaces@domain.com"
        ]
        
        for email in invalid_emails:
            result = validate_email_address(email)
            assert result["valid"] is False, f"'{email}' ne devrait pas être valide"
            assert len(result["errors"]) > 0

class TestPasswordValidation:
    """Tests de validation de mot de passe selon ASVS V6.2.1-V6.2.5."""
    
    def test_password_length_validation(self):
        """Test ASVS V6.2.1 - Longueur minimale de 12 caractères."""
        # Mots de passe trop courts
        short_passwords = ["password", "12345678901", "Abc123!"]
        
        for password in short_passwords:
            result = validate_password(password)
            assert result["valid"] is False
            assert any("12 caractères" in error for error in result["errors"])
        
        # Mot de passe de longueur minimale valide
        result = validate_password("ValidPass123!")
        # Peut être valide si passe tous les autres critères
    
    def test_password_complexity_validation(self):
        """Test ASVS V6.2.2 - Complexité (3/4 types de caractères)."""
        test_cases = [
            ("abcdefghijklmnop", False, "Que des minuscules"),
            ("ABCDEFGHIJKLMNOP", False, "Que des majuscules"), 
            ("1234567890123456", False, "Que des chiffres"),
            ("!@#$%^&*()_+-=[]", False, "Que des symboles"),
            ("abcABC123456789", True, "3 types: min+maj+chiffres"),
            ("abcABC!@#$%^&*(", True, "3 types: min+maj+symboles"),
            ("abc123!@#$%^&*(", True, "3 types: min+chiffres+symboles"),
            ("ABC123!@#$%^&*(", True, "3 types: maj+chiffres+symboles"),
            ("abcABC123!@#$%^", True, "4 types: tous")
        ]
        
        for password, should_be_valid, description in test_cases:
            result = validate_password(password)
            if should_be_valid:
                # Peut être invalide pour d'autres raisons, mais pas la complexité
                complexity_errors = [e for e in result["errors"] if "types de caractères" in e]
                assert len(complexity_errors) == 0, f"{description}: pas d'erreur de complexité"
            else:
                assert any("types de caractères" in error for error in result["errors"]), \
                    f"{description}: devrait avoir une erreur de complexité"
    
    def test_password_username_validation(self):
        """Test ASVS V6.2.3 - Le mot de passe ne doit pas être le nom d'utilisateur."""
        result = validate_password("testuser123!", "testuser")
        # Devrait être valide car différent du username
        username_errors = [e for e in result["errors"] if "nom d'utilisateur" in e]
        assert len(username_errors) == 0
        
        # Test avec mot de passe identique au username
        result = validate_password("testuser", "testuser")
        assert any("nom d'utilisateur" in error for error in result["errors"])
    
    def test_password_repetition_validation(self):
        """Test ASVS V6.2.4 - Pas plus de 2 caractères consécutifs identiques."""
        invalid_passwords = [
            "PassWord111aaa", "MDP123333BBB", "Test@@@456789"
        ]
        
        for password in invalid_passwords:
            result = validate_password(password)
            assert any("caractères identiques consécutifs" in error for error in result["errors"])
        
        # Mots de passe valides (max 2 caractères consécutifs)
        valid_passwords = [
            "PassWord11AA", "MDP123BB@456"
        ]
        
        for password in valid_passwords:
            result = validate_password(password)
            repetition_errors = [e for e in result["errors"] if "caractères identiques consécutifs" in e]
            assert len(repetition_errors) == 0
    
    def test_common_passwords_validation(self):
        """Test ASVS V6.2.5 - Vérification contre les mots de passe courants."""
        # Charger les mots de passe courants pour le test
        common_passwords = load_common_passwords()
        
        if len(common_passwords) > 0:
            # Test avec un mot de passe courant (en supposant que "password" est dans la liste)
            result = validate_password("password123456789")
            # Peut être invalide pour d'autres raisons, vérifier spécifiquement l'erreur des mots de passe courants
            
            # Test avec "123456" qui devrait être dans la liste
            result = validate_password("123456789012")
            assert any("couramment utilisés" in error for error in result["errors"])
    
    def test_sequence_validation(self):
        """Test contre les suites de caractères simples."""
        invalid_passwords = [
            "Password123456789", "MDP@qwertyuiop",
            "Secure0123456789"
        ]
        
        for password in invalid_passwords:
            result = validate_password(password)
            assert any("suites de caractères" in error for error in result["errors"])
    
    def test_valid_passwords(self):
        """Test avec des mots de passe entièrement valides."""
        valid_passwords = [
            "MySecure@Pass2024", "Complex!Pass456",
            "Strong#Pwd789AB", "Valid@Secret123"
        ]
        
        for password in valid_passwords:
            result = validate_password(password)
            # Ces mots de passe peuvent être invalides s'ils sont dans la liste des mots de passe courants
            # mais devraient passer tous les autres critères

class TestPasswordHashing:
    """Tests pour le hachage et la vérification des mots de passe."""
    
    def test_password_hashing(self):
        """Test du hachage de mot de passe avec Argon2id."""
        password = "TestPassword123!"
        
        # Hacher le mot de passe
        hashed = hash_password(password)
        
        # Vérifier que le hash a été créé
        assert hashed is not None
        assert len(hashed) > 0
        assert hashed != password  # Le hash ne doit pas être identique au mot de passe
        
        # Vérifier que le hash contient les marqueurs Argon2id
        assert "$argon2id$" in hashed
    
    def test_password_verification(self):
        """Test de la vérification de mot de passe."""
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        
        # Hacher le mot de passe correct
        hashed = hash_password(password)
        
        # Vérifier avec le bon mot de passe
        assert verify_password(password, hashed) is True
        
        # Vérifier avec le mauvais mot de passe
        assert verify_password(wrong_password, hashed) is False
    
    def test_hash_uniqueness(self):
        """Test que chaque hachage produit un résultat unique (grâce au sel)."""
        password = "TestPassword123!"
        
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Les hashs doivent être différents (sels différents)
        assert hash1 != hash2
        
        # Mais les deux doivent vérifier le même mot de passe
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True

@patch('auth_register.get_connection')
class TestUserRegistration:
    """Tests pour l'inscription utilisateur."""
    
    def test_successful_registration(self, mock_get_connection):
        """Test d'inscription réussie."""
        # Mock de la connexion base de données
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 123
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Mock pour vérifier la disponibilité (utilisateur n'existe pas)
        mock_cursor.fetchone.return_value = None
        
        result = register_user("newuser", "new@example.com", "ValidPassword123!")
        
        assert result["success"] is True
        assert "user_id" in result
        assert result["user_id"] == 123
    
    def test_registration_with_invalid_data(self, mock_get_connection):
        """Test d'inscription avec données invalides."""
        result = register_user("", "invalid-email", "weak")
        
        assert result["success"] is False
        assert len(result["errors"]) > 0
        
        # Vérifier que les erreurs incluent les problèmes identifiés
        errors_text = " ".join(result["errors"]).lower()
        assert "nom d'utilisateur" in errors_text
        assert "email" in errors_text or "adresse" in errors_text
        assert "12 caractères" in errors_text or "mot de passe" in errors_text

@patch('auth_register.get_connection')
class TestPasswordChange:
    """Tests pour le changement de mot de passe."""
    
    def test_successful_password_change(self, mock_get_connection):
        """Test de changement de mot de passe réussi."""
        # Mock de la base de données
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Hash du mot de passe actuel
        current_password = "CurrentPass123!"
        current_hash = hash_password(current_password)
        
        # Mock du résultat de la requête utilisateur
        mock_cursor.fetchone.return_value = ("testuser", current_hash)
        
        new_password = "NewPassword456!"
        result = change_password(1, current_password, new_password)
        
        assert result["success"] is True
        assert "message" in result
    
    def test_password_change_with_wrong_current(self, mock_get_connection):
        """Test avec mauvais mot de passe actuel."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Hash d'un mot de passe différent
        current_hash = hash_password("DifferentPassword123!")
        mock_cursor.fetchone.return_value = ("testuser", current_hash)
        
        result = change_password(1, "WrongPassword123!", "NewPassword456!")
        
        assert result["success"] is False
        assert any("incorrect" in error for error in result["errors"])

class TestUtilityFunctions:
    """Tests pour les fonctions utilitaires."""
    
    def test_load_common_passwords(self):
        """Test du chargement de la liste des mots de passe courants."""
        passwords = load_common_passwords()
        
        # Vérifier que c'est un set
        assert isinstance(passwords, set)
        
        # Devrait contenir au moins quelques mots de passe
        if len(passwords) > 0:
            # Vérifier que des mots de passe courants connus sont présents
            common_ones = {"123456", "password", "qwerty"}
            found = common_ones.intersection(passwords)
            assert len(found) > 0, "Devrait contenir au moins un mot de passe courant connu"

if __name__ == "__main__":
    # Exécuter les tests avec pytest
    pytest.main([__file__, "-v"])