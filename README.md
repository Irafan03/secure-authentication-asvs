# Système d'authentification sécurisé - OWASP ASVS 5.0.0

Bibliothèque d'authentification Python conforme au niveau L2 de l'OWASP ASVS 5.0.0 (Application Security Verification Standard) pour le chapitre V6 (Authentification).

## 🔒 Niveau de sécurité

**✅ ASVS 5.0.0 Niveau L2 (Complet)**

- 20/20 exigences applicables respectées (100%)
- Documentation complète de conformité disponible

## 📋 Fonctionnalités

### Authentification de base
- ✅ Validation robuste des mots de passe (12-128 caractères, pas de règles de composition)
- ✅ Hachage Argon2id avec paramètres sécurisés
- ✅ Vérification mots de passe compromis (HIBP + liste locale 3000+)
- ✅ Protection contre les mots contextuels

### Protection contre les attaques
- ✅ Rate limiting multi-niveaux (IP, user+IP, username)
- ✅ Protection contre le déni de service sur compte
- ✅ Protection timing attack (hash factice)
- ✅ Messages d'erreur génériques (pas d'énumération)

### Authentification multi-facteurs (MFA)
- ✅ MFA obligatoire par TOTP (Google Authenticator compatible)
- ✅ QR code pour enrôlement facile
- ✅ Codes de récupération à usage unique (hachés avec Argon2)
- ✅ Anti-rejeu de codes TOTP
- ✅ Rate limiting appliqué au MFA

### Gestion des sessions
- ✅ Tokens de session cryptographiquement sûrs (256 bits)
- ✅ Expiration automatique (8 heures par défaut)
- ✅ Invalidation manuelle (logout)

## 📚 Documentation

- **[Conformité ASVS](docs/ASVS_V6_CONFORMITE.md)** : Documentation complète de conformité avec tableau détaillé des 29 exigences
- **[Progression](docs/ASVS_PROGRESS.md)** : Historique des tâches et corrections effectuées
- **[Voies d'authentification](docs/AUTHENTICATION_PATHS.md)** : Liste des voies d'authentification et contrôles

## 🌐 Interface Web

Cette application inclut une interface web complète construite avec Flask pour tester et démontrer les fonctionnalités d'authentification sécurisée.

### Fonctionnalités de l'interface

- 🎨 **Design professionnel** : Interface moderne avec Bootstrap 5, gradient violet/bleu
- 📱 **Responsive** : Compatible desktop, tablette et mobile
- 🔐 **Inscription sécurisée** : Validation en temps réel, indicateur de force du mot de passe
- 🚪 **Connexion** : Support MFA, messages d'erreur génériques
- 📊 **Tableau de bord** : Statistiques du compte, gestion MFA
- 📲 **Enrôlement MFA** : QR code, codes de récupération téléchargeables
- ⚠️ **Pages d'erreur** : 404 et 500 personnalisées

### Démarrage rapide

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer la base de données
cp .env.example .env
# Éditez .env avec vos paramètres MySQL

# 3. Charger les variables d'environnement
source .env

# 4. Lancer l'application
python3 app.py

# L'application sera disponible sur http://localhost:5000
```

**📖 Guide complet : Consultez [GUIDE_DEMARRAGE.md](GUIDE_DEMARRAGE.md) pour des instructions détaillées**

## 🚀 Installation (mode bibliothèque)

```bash
# Cloner le projet
git clone <repository-url>
cd secure-authentication-asvs

# Créer un environnement virtuel
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt
```

## ⚙️ Configuration

### Base de données

Configurer les variables d'environnement :

```bash
export DB_HOST=localhost
export DB_PORT=3306
export DB_USER=app_user
export DB_PASSWORD=your_secure_password
export DB_NAME=secure_auth
```

### Initialisation du schéma

```python
from database import init_db

# Créer les tables
init_db()
```

## 💻 Utilisation

### Inscription d'un utilisateur

```python
from auth_register import register_user

result = register_user(
    username="johndoe",
    email="john@example.com",
    password="MySecurePassword123"
)

if result["success"]:
    user_id = result["user_id"]
    print(f"Utilisateur créé avec l'ID: {user_id}")
else:
    print("Erreurs:", result["errors"])
```

### Authentification

```python
from auth_login import authenticate_user

result = authenticate_user(
    username="johndoe",
    password="MySecurePassword123",
    ip_address="192.168.1.100"
)

if result["success"]:
    session_token = result["session_token"]
    print(f"Connexion réussie, token: {session_token}")
elif result.get("mfa_required"):
    print("Second facteur requis")
else:
    print("Erreurs:", result["errors"])
```

### Enrôlement MFA

```python
from auth_mfa import enroll_mfa, validate_mfa_enrollment

# Enrôler l'utilisateur dans le MFA
result = enroll_mfa(user_id, username="johndoe")

if result["success"]:
    print("QR Code URI:", result["qr_code_uri"])
    print("Codes de récupération:", result["recovery_codes"])
    
    # L'utilisateur scanne le QR code et entre son premier code TOTP
    first_code = input("Entrez le code TOTP: ")
    
    # Valider l'enrôlement
    if validate_mfa_enrollment(user_id, first_code):
        print("MFA activé avec succès!")
```

### Authentification avec MFA

```python
# Premier facteur (mot de passe)
result = authenticate_user(
    username="johndoe",
    password="MySecurePassword123",
    ip_address="192.168.1.100"
)

if result.get("mfa_required"):
    # Second facteur (code TOTP)
    totp_code = input("Entrez le code TOTP: ")
    
    result = authenticate_user(
        username="johndoe",
        password="MySecurePassword123",
        ip_address="192.168.1.100",
        totp_code=totp_code
    )
    
    if result["success"]:
        print("Authentification complète réussie!")
```

## 🧪 Tests

```bash
# Tests de validation (sans DB)
pytest tests/test_password_validation.py -v

# Tests de niveau 2 (MFA, mots contextuels)
pytest tests/test_asvs_level2.py -v

# Tests complets de niveau 1 (nécessite DB configurée)
pytest tests/test_asvs_level1.py -v

# Tous les tests avec couverture
pytest --cov=. --cov-report=html
```

## 🔧 Configuration avancée

Tous les paramètres de sécurité sont centralisés dans `config.py` :

```python
# Mots de passe
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

# Rate limiting
RATE_LIMIT_IP_MAX_ATTEMPTS = 20
RATE_LIMIT_USER_IP_MAX_ATTEMPTS = 5
RATE_LIMIT_USERNAME_MAX_ATTEMPTS = 50

# MFA
TOTP_INTERVAL = 30  # secondes
RECOVERY_CODES_COUNT = 10

# Sessions
SESSION_DURATION = timedelta(hours=8)
```

## 📊 Paramètres de sécurité

### Rate Limiting

- **Par IP** : 20 tentatives / 15 min → blocage 30 min
- **Par (username, IP)** : 5 tentatives / 10 min → blocage 15 min
- **Par username** : 50 tentatives / 1h avec délai progressif

### Hachage

- **Algorithme** : Argon2id
- **Paramètres** : 3 iterations, 64 MB mémoire, 4 threads
- **Sel** : 16 bytes aléatoires

### MFA

- **Type** : TOTP (Time-based One-Time Password)
- **Durée** : 30 secondes
- **Chiffres** : 6
- **Secret** : 256 bits (CSPRNG)
- **Codes récupération** : 10 codes, hachés avec Argon2

## ⚠️ Limites connues

### Contrôles frontend requis

Les contrôles suivants doivent être implémentés dans le frontend :

- Autoriser le collage de mots de passe
- Attribut `autocomplete` adapté
- Pas de hints de mot de passe affichés

### Fonctionnalités non incluses

- Reset de mot de passe par email (nécessite service d'envoi)
- Authentification SMS/email OOB
- Authentification par certificat
- IdP externe (OAuth, SAML)
- Notifications de sécurité par email

## 📖 Standards et références

- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [Argon2 Password Hashing](https://github.com/P-H-C/phc-winner-argon2)
- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)

## 📄 Licence

[Votre licence ici]

## 👥 Contributeurs

[Vos contributeurs ici]

---

**Version** : 1.0.0  
**Date** : 2026-10-16  
**Conformité ASVS** : Niveau L2 (100%)
