# 🚀 Guide de démarrage rapide

## Prérequis

- Python 3.8+
- MySQL 8.0+
- pip (gestionnaire de packages Python)

## Installation

### 1. Cloner le dépôt (si applicable)

```bash
cd secure-authentication-asvs
```

### 2. Créer un environnement virtuel

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate  # Windows
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Configurer la base de données MySQL

#### Créer la base de données

```bash
mysql -u root -p
```

Dans MySQL :

```sql
CREATE DATABASE secure_auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'secure_auth_user'@'localhost' IDENTIFIED BY 'VotreMotDePasseSecurise123!';
GRANT ALL PRIVILEGES ON secure_auth_db.* TO 'secure_auth_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

#### Configurer les variables d'environnement

Créez un fichier `.env` à la racine du projet :

```bash
# Base de données
export DB_HOST=localhost
export DB_PORT=3306
export DB_NAME=secure_auth_db
export DB_USER=secure_auth_user
export DB_PASSWORD=VotreMotDePasseSecurise123!

# Flask
export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export FLASK_ENV=development

# MFA
export TOTP_ISSUER="SecureAuth ASVS"
```

Charger les variables :

```bash
source .env
```

### 5. Initialiser la base de données

Les tables seront créées automatiquement au premier démarrage de l'application.

Pour initialiser manuellement :

```bash
python3 -c "from backend.database import init_db; init_db()"
```

## Démarrage de l'application

### Mode développement

```bash
python3 -m backend.app
```

L'application sera accessible sur : **http://localhost:5000**

### Mode production (avec Gunicorn)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app
```

## Test de l'application

### 1. Accéder à l'interface web

Ouvrez votre navigateur : http://localhost:5000

### 2. Créer un compte

- Cliquez sur "S'inscrire"
- Remplissez le formulaire :
  - **Nom d'utilisateur** : minimum 3 caractères
  - **Email** : valide
  - **Mot de passe** : minimum 12 caractères (sans règles de composition)
- Le système vérifie automatiquement si le mot de passe est compromis (HIBP + liste locale)

### 3. Se connecter

- Utilisez vos identifiants
- Le système applique le rate limiting (protection anti-brute force)
- Si le MFA est activé, entrez votre code TOTP

### 4. Activer le MFA (recommandé)

1. Connectez-vous à votre compte
2. Sur le tableau de bord, cliquez sur "Activer le MFA"
3. Scannez le QR code avec une application d'authentification :
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
   - FreeOTP
4. **IMPORTANT** : Sauvegardez les codes de récupération
5. Entrez le code TOTP généré pour valider

### 5. Tester le MFA

- Déconnectez-vous
- Reconnectez-vous : vous devrez entrer le code TOTP

## Exécution des tests

### Tests unitaires

```bash
pytest
```

### Tests avec couverture

```bash
pytest --cov=. --cov-report=html
```

Le rapport sera disponible dans `htmlcov/index.html`

### Tests spécifiques

```bash
# Tests de validation de mot de passe
pytest tests/test_password_validation.py -v

# Tests ASVS niveau 1
pytest tests/test_asvs_level1.py -v

# Tests ASVS niveau 2
pytest tests/test_asvs_level2.py -v

# Tests d'inscription
pytest tests/test_register.py -v
```

## Structure du projet

```
secure-authentication-asvs/
├── backend/                     # Package Python du backend
│   ├── backend/app.py                   # Application Flask
│   ├── auth_*.py                # Authentification et MFA
│   ├── backend/config.py                # Configuration centralisée
│   ├── backend/database.py              # Gestion base de données
│   └── ...
├── backend/auth_register.py            # Module d'inscription
├── backend/auth_login.py               # Module de connexion
├── backend/auth_mfa.py                 # Module MFA/TOTP
├── backend/database.py                 # Gestion base de données
├── backend/config.py                   # Configuration centralisée
├── requirements.txt            # Dépendances Python
├── backend/common_passwords.txt        # Liste 3000+ mots de passe courants
├── templates/                  # Templates HTML
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── mfa_enroll.html
│   ├── 404.html
│   └── 500.html
├── tests/                      # Tests unitaires
│   ├── test_password_validation.py
│   ├── test_asvs_level1.py
│   ├── test_asvs_level2.py
│   └── test_register.py
└── docs/                       # Documentation
    ├── ASVS_PROGRESS.md
    ├── ASVS_V6_CONFORMITE.md
    └── AUTHENTICATION_PATHS.md
```

## Fonctionnalités principales

### ✅ Conformité ASVS 5.0.0 - Niveau L2 (100%)

- **20/20 exigences applicables respectées**
- Validation de mot de passe sécurisée (V6.2)
- Rate limiting multi-niveaux (V6.3)
- MFA obligatoire par TOTP (V6.5)
- Protection contre les attaques timing (V6.3.8)
- Vérification HIBP avec k-anonymity (V6.2.4)

### 🔐 Sécurité

- **Hachage Argon2id** pour les mots de passe
- **Rate limiting** : IP, user+IP, username
- **MFA/TOTP** : SHA-256, 6 chiffres, 30 secondes
- **Anti-rejeu** : codes TOTP et récupération à usage unique
- **Sessions sécurisées** avec tokens expirables
- **Protection timing attack** avec hashes factices

### 🎨 Interface utilisateur

- Design professionnel avec Bootstrap 5
- Gradient moderne (violet/bleu)
- Responsive et accessible
- Indicateur de force du mot de passe
- Validation en temps réel
- Messages d'erreur génériques (anti-énumération)

## Configuration avancée

### Paramètres de sécurité (backend/config.py)

```python
# Rate limiting
RATE_LIMIT_IP = 50              # Tentatives/heure par IP
RATE_LIMIT_USER_IP = 10         # Tentatives/heure par user+IP
RATE_LIMIT_USERNAME = 5         # Tentatives/heure par username

# Mot de passe
PASSWORD_MIN_LENGTH = 12        # Minimum 12 caractères
PASSWORD_MAX_LENGTH = 128       # Maximum 128 caractères

# MFA
TOTP_INTERVAL = 30              # Durée validité code (secondes)
TOTP_DIGITS = 6                 # Nombre de chiffres
RECOVERY_CODES_COUNT = 10       # Nombre de codes de récupération
```

### Variables d'environnement

| Variable | Description | Exemple |
|----------|-------------|---------|
| `DB_HOST` | Hôte MySQL | `localhost` |
| `DB_PORT` | Port MySQL | `3306` |
| `DB_NAME` | Nom de la base | `secure_auth_db` |
| `DB_USER` | Utilisateur MySQL | `secure_auth_user` |
| `DB_PASSWORD` | Mot de passe MySQL | `SecurePass123!` |
| `FLASK_SECRET_KEY` | Clé secrète Flask | Token 32+ bytes |
| `TOTP_ISSUER` | Nom dans l'app MFA | `SecureAuth ASVS` |

## Dépannage

### Erreur de connexion MySQL

```
mysql.connector.errors.ProgrammingError: Access denied
```

**Solution** : Vérifiez les variables d'environnement `DB_USER` et `DB_PASSWORD`

### Erreur "No module named 'flask'"

```bash
pip install Flask==3.0.3
```

### Port 5000 déjà utilisé

Changez le port dans `backend/app.py` :

```python
app.run(debug=True, host='0.0.0.0', port=8000)
```

### Échec de l'initialisation de la base

Vérifiez les permissions MySQL :

```sql
SHOW GRANTS FOR 'secure_auth_user'@'localhost';
```

## Production

### ⚠️ Avant de déployer en production

1. **Désactiver le mode debug** dans `backend/app.py` :
   ```python
   app.run(debug=False)
   ```

2. **Activer HTTPS** :
   ```python
   app.config['SESSION_COOKIE_SECURE'] = True
   ```

3. **Générer une clé secrète forte** :
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

4. **Configurer un serveur WSGI** (Gunicorn, uWSGI)

5. **Mettre en place un reverse proxy** (Nginx, Apache)

6. **Sauvegarder régulièrement** la base de données

7. **Activer les logs** et la surveillance

## Support

Pour toute question ou problème :

1. Consultez la documentation dans `/docs`
2. Vérifiez les logs de l'application
3. Exécutez les tests : `pytest -v`

## Conformité ASVS

Consultez la documentation détaillée :

- `docs/ASVS_V6_CONFORMITE.md` : Tableau complet des 29 exigences
- `docs/ASVS_PROGRESS.md` : Progression et résumé
- `docs/AUTHENTICATION_PATHS.md` : Voies d'authentification

---

**Version** : 1.0.0  
**Conformité** : OWASP ASVS 5.0.0 - Niveau L2 (100%)  
**Licence** : MIT
