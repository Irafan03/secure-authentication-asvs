"""
test_password_change.py — Tests spécifiques pour le changement de mot de passe
ASVS v4.0 — Niveau 2
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from datetime import datetime

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.auth_register import (
    change_password, hash_password, verify_password,
    validate_password, get_user_by_id
)

class TestPasswordChangeValidation:
    """Tests pour la validation lors du changement de mot de passe."""
    
    def test_password_change_validation_rules(self):
        """Test que les mêmes règles de validation s'appliquent."""
        # Test avec un nouveau mot de passe invalide
        with patch('auth_register.get_connection') as mock_get_connection:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_get_connection.return_value.__enter__.return_value = mock_conn
            
            # Simuler un utilisateur existant avec un mot de passe haché
            current_password = "ValidCurrent123!"
            current_hash = hash_password(current_password)
            mock_cursor.fetchone.return_value = ("testuser", current_hash)
            
            # Test avec nouveau mot de passe trop court
            result = change_password(1, current_password, "short")
            assert result["success"] is False
            assert any("12 caractères" in error for error in result["errors"])
            
            # Test avec nouveau mot de passe contenant un mot contextuel (ASVS 6.2.11)
            result = change_password(1, current_password, "MySecurePassword123")
            assert result["success"] is False
            assert any("contexte de l'application" in error for error in result["errors"])
            
            # Test avec mot de passe courant
            result = change_password(1, current_password, "password123456789")
            assert result["success"] is False
    
    def test_same_password_rejection(self):
        """Test que l'ancien et le nouveau mot de passe ne peuvent pas être identiques."""
        with patch('auth_register.get_connection') as mock_get_connection:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_get_connection.return_value.__enter__.return_value = mock_conn
            
            # Utiliser le même mot de passe pour l'ancien et le nouveau
            password = "SamePassword123!"
            password_hash = hash_password(password)
            mock_cursor.fetchone.return_value = ("testuser", password_hash)
            
            result = change_password(1, password, password)
            assert result["success"] is False
            assert any("différent de l'ancien" in error for error in result["errors"])

@patch('auth_register.get_connection')
class TestPasswordChangeScenarios:
    """Tests pour différents scénarios de changement de mot de passe."""
    
    def test_successful_password_change(self, mock_get_connection):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Simuler un utilisateur existant
        current_password = "CurrentValid123!"
        current_hash = hash_password(current_password)
        mock_cursor.fetchone.return_value = ("testuser", current_hash)
        
        # Nouveau mot de passe valide et différent
        new_password = "NewComplexPass456@"
        result = change_password(1, current_password, new_password)
        
        assert result["success"] is True
        assert "message" in result
        assert "succès" in result["message"]
        
        # Vérifier que la base de données a été mise à jour
        mock_cursor.execute.assert_called()
        calls = mock_cursor.execute.call_args_list

        # La dernière requête devrait être l'UPDATE
        last_call = calls[-1]
        assert "UPDATE users SET password_hash" in last_call[0][0]
    
    def test_wrong_current_password(self, mock_get_connection):
        """Test avec un mauvais mot de passe actuel."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Hash d'un mot de passe différent
        actual_password = "ActualPassword123!"
        password_hash = hash_password(actual_password)
        mock_cursor.fetchone.return_value = ("testuser", password_hash)
        
        # Essayer avec un mauvais mot de passe actuel
        result = change_password(1, "WrongPassword123!", "NewPassword456@")
        
        assert result["success"] is False
        assert any("incorrect" in error.lower() for error in result["errors"])
    
    def test_user_not_found(self, mock_get_connection):
        """Test avec un utilisateur introuvable."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Simuler qu'aucun utilisateur n'est trouvé
        mock_cursor.fetchone.return_value = None
        
        result = change_password(999, "AnyPassword123!", "NewPassword456@")
        
        assert result["success"] is False
        assert any("introuvable" in error or "inactif" in error for error in result["errors"])
    
    def test_inactive_user(self, mock_get_connection):
        """Test avec un utilisateur inactif."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Simuler un utilisateur inactif (is_active = 0)
        current_password = "CurrentPassword123!"
        password_hash = hash_password(current_password)
        
        # La requête SQL vérifie is_active = 1, donc un utilisateur inactif ne sera pas trouvé
        mock_cursor.fetchone.return_value = None
        
        result = change_password(1, current_password, "NewPassword456@")
        
        assert result["success"] is False
        assert any("introuvable" in error or "inactif" in error for error in result["errors"])
    
    def test_database_error_handling(self, mock_get_connection):
        """Test de gestion des erreurs de base de données."""
        # Simuler une erreur de base de données
        mock_get_connection.side_effect = Exception("Database connection failed")
        
        result = change_password(1, "CurrentPassword123!", "NewPassword456@")
        
        assert result["success"] is False
        assert any("erreur" in error.lower() for error in result["errors"])

class TestPasswordChangeValidationEdgeCases:
    """Tests pour les cas limites de validation des mots de passe."""
    
    @patch('auth_register.get_connection')
    def test_maximum_length_password(self, mock_get_connection):
        """Test avec un mot de passe à la longueur maximale."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        current_password = "CurrentPassword123!"
        current_hash = hash_password(current_password)
        mock_cursor.fetchone.return_value = ("testuser", current_hash)
        
        # Mot de passe de 128 caractères (limite max)
        max_password = "A1@" + "b" * 125  # 128 caractères total
        
        result = change_password(1, current_password, max_password)
        
        # Devrait être accepté s'il respecte les autres critères
        length_errors = [e for e in result.get("errors", []) if "128 caractères" in e]
        assert len(length_errors) == 0
        
        # Tester avec plus de 128 caractères
        too_long_password = "A1@" + "b" * 126  # 129 caractères
        
        result = change_password(1, current_password, too_long_password)
        assert result["success"] is False
        assert any("128 caractères" in error for error in result["errors"])
    
    @patch('auth_register.get_connection')
    def test_unicode_password_support(self, mock_get_connection):
        """Test avec des caractères Unicode dans le mot de passe."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        current_password = "CurrentPassword123!"
        current_hash = hash_password(current_password)
        mock_cursor.fetchone.return_value = ("testuser", current_hash)
        
        # Mot de passe avec caractères Unicode
        unicode_password = "MétDéPâssé123!€"
        
        result = change_password(1, current_password, unicode_password)
        
        # Le système devrait gérer les caractères Unicode
        # (peut être invalide pour d'autres raisons mais pas à cause de l'Unicode)
    
    @patch('auth_register.get_connection')
    def test_username_similarity_check(self, mock_get_connection):
        """Test que le nouveau mot de passe ne peut pas être similaire au nom d'utilisateur."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        current_password = "CurrentPassword123!"
        current_hash = hash_password(current_password)
        username = "johndoe"
        mock_cursor.fetchone.return_value = (username, current_hash)
        
        # Essayer de définir un mot de passe identique au nom d'utilisateur
        result = change_password(1, current_password, username)
        
        assert result["success"] is False
        # Devrait échouer à cause de la longueur ET de la similarité au username

class TestPasswordChangeIntegration:
    """Tests d'intégration pour le changement de mot de passe."""
    
    @patch('auth_register.get_connection')
    def test_full_password_change_workflow(self, mock_get_connection):
        """Test du workflow complet de changement de mot de passe."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        # Étape 1: Utilisateur existant avec mot de passe valide
        user_id = 42
        username = "testuser"
        old_password = "OldSecurePassword123!"
        old_hash = hash_password(old_password)
        
        mock_cursor.fetchone.return_value = (username, old_hash)
        
        # Étape 2: Nouveau mot de passe valide et différent
        new_password = "NewComplexPassword456@"
        
        # Étape 3: Effectuer le changement
        result = change_password(user_id, old_password, new_password)
        
        # Étape 4: Vérifier le succès
        assert result["success"] is True
        
        # Étape 5: Vérifier que les bonnes requêtes SQL ont été exécutées
        calls = mock_cursor.execute.call_args_list
        
        # Première requête: SELECT pour récupérer l'utilisateur
        select_call = calls[0]
        assert "SELECT" in select_call[0][0]
        assert "users" in select_call[0][0]
        assert select_call[0][1] == (user_id,)
        
        # Deuxième requête: UPDATE pour changer le mot de passe
        update_call = calls[1]
        assert "UPDATE users SET password_hash" in update_call[0][0]
        
        # Vérifier que le nouveau hash est différent de l'ancien
        new_hash = update_call[0][1][0]
        assert new_hash != old_hash
        assert verify_password(new_password, new_hash)
    
    @patch('auth_register.get_connection')
    def test_concurrent_password_changes(self, mock_get_connection):
        """Test de gestion des changements de mot de passe concurrents."""
        # Ce test simule ce qui se passerait si deux changements de mot de passe
        # étaient tentés simultanément
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_connection.return_value.__enter__.return_value = mock_conn
        
        user_id = 1
        username = "testuser"
        original_password = "OriginalPassword123!"
        original_hash = hash_password(original_password)
        
        # Premier changement réussi
        mock_cursor.fetchone.return_value = (username, original_hash)
        
        result1 = change_password(user_id, original_password, "NewPassword456@")
        assert result1["success"] is True
        
        # Deuxième changement avec l'ancien mot de passe (devrait échouer)
        # Car entre-temps le mot de passe a changé
        new_hash = hash_password("NewPassword456@")
        mock_cursor.fetchone.return_value = (username, new_hash)
        
        result2 = change_password(user_id, original_password, "AnotherPassword789#")
        assert result2["success"] is False
        assert any("incorrect" in error for error in result2["errors"])

if __name__ == "__main__":
    # Exécuter les tests avec pytest
    pytest.main([__file__, "-v"])