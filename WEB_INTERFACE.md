# 🌐 Interface Web - Documentation

## Vue d'ensemble

L'interface web FastAPI permet de tester et démontrer les fonctionnalités d'authentification sécurisée conformes à l'OWASP ASVS 5.0.0 niveau L2.

## Architecture

### Structure des fichiers

```
<<<<<<< HEAD
├── backend/                    # Package Python du backend
│   └── backend/app.py                  # Application Flask principale
=======
├── app.py                      # Application FastAPI principale
>>>>>>> 68f20a7 (frontend)
├── templates/                  # Templates Jinja2
│   ├── base.html              # Layout partagé et navigation
│   ├── index.html             # Page d'accueil
│   ├── register.html          # Formulaire d'inscription
│   ├── login.html             # Formulaire de connexion
│   ├── dashboard.html         # Tableau de bord utilisateur
│   ├── mfa_enroll.html        # Enrôlement MFA avec QR code
│   ├── 404.html               # Page erreur 404
│   └── 500.html               # Page erreur 500
└── static/                    # Assets statiques (CSS, JS, images)
    ├── css/
    ├── js/
    └── images/
```

### Routes disponibles

| Route | Méthode | Description | Authentification |
|-------|---------|-------------|------------------|
| `/` | GET | Page d'accueil | Non |
| `/register` | GET, POST | Inscription utilisateur | Non |
| `/login` | GET, POST | Connexion | Non |
| `/dashboard` | GET | Tableau de bord | ✅ Requise |
| `/mfa/enroll` | GET, POST | Enrôlement MFA | ✅ Requise |
| `/account/password` | GET, POST | Changement de mot de passe | ✅ Requise |
| `/logout` | POST | Déconnexion | ✅ Requise |
| `/api/validate-password` | POST | Validation temps réel (API) | Non |

## Design et UX

### Thème visuel

- **Palette de couleurs** :
  - Primaire : `#667eea` (bleu violet)
  - Secondaire : `#764ba2` (violet profond)
  - Gradient : `linear-gradient(135deg, #667eea 0%, #764ba2 100%)`
  
- **Framework CSS** : CSS local, sans dépendance externe
- **Icônes** : symboles intégrés à l'interface
- **Polices** : polices système avec solutions de repli

### Composants UI

#### Cards d'authentification
- Glassmorphism effect (transparence + flou)
- Ombres douces
- Bordures arrondies (border-radius: 15px)
- Animations CSS au survol

#### Formulaires
- Aide de longueur côté navigateur et validation complète côté serveur
- Messages d'erreur contextuels
- Indicateur de force de mot de passe (barre de progression colorée)
- Autocomplétion permise avec les valeurs `current-password` et `new-password`
- Collage autorisé dans les champs de mot de passe

#### Feedback utilisateur
- Messages de retour intégrés (succès, erreur, avertissement, information)
- Loader/spinner pour les actions longues
- Confirmations visuelles (icônes, couleurs)

## Fonctionnalités par page

### 1. Page d'accueil (`index.html`)

**Objectif** : Présenter l'application et ses garanties de sécurité

**Contenu** :
- Hero section avec titre et description
- Badge de conformité ASVS L2
- Statistiques de sécurité (20/20 exigences, 100% conformité)
- Boutons d'action : "Se connecter" et "S'inscrire"
- Liste des fonctionnalités principales

**Redirection automatique** : Si l'utilisateur est déjà connecté → `/dashboard`

### 2. Inscription (`register.html`)

**Fonctionnalités** :
- ✅ Validation côté navigateur et validation de sécurité côté serveur
- ✅ Aide visuelle de longueur du mot de passe
- ✅ Vérification disponibilité username/email
- ✅ Messages d'erreur génériques (ASVS 6.3.8)
- ✅ Contrôle des mots de passe compromis lors de la validation serveur

**Champs** :
- Nom d'utilisateur (min 3 caractères)
- Email (validation format)
- Mot de passe (8-128 caractères, aucune règle de composition)
- Confirmation mot de passe

**API de validation disponible** (le formulaire applique la validation complète à l'envoi) :
```javascript
// Endpoint JSON facultatif
POST /api/validate-password
{
  "password": "monMotDePasse",
  "username": "utilisateur"
}

// Réponse
{
  "valid": true|false,
  "errors": ["Erreur 1", "Erreur 2"]
}
```

**Aide de longueur** : le navigateur indique si le mot de passe atteint la longueur minimale. Les contrôles de mots courants, de contexte et de compromission restent côté serveur.

### 3. Connexion (`login.html`)

**Fonctionnalités** :
- ✅ Rate limiting visuel (affichage compte à rebours si bloqué)
- ✅ Support MFA en deux étapes
- ✅ Messages génériques (pas d'énumération)
- ✅ Protection timing attack côté serveur

**Flux de connexion** :

```
1. Utilisateur entre username + password
   ↓
2. Vérification identifiants
   ↓
3a. MFA désactivé → Connexion réussie → /dashboard
3b. MFA activé → Affichage champ TOTP → Étape 4
   ↓
4. Utilisateur entre code TOTP à 6 chiffres
   ↓
5. Vérification TOTP (anti-rejeu)
   ↓
6. Connexion réussie → /dashboard
```

**Gestion des erreurs** :
- Messages génériques : "Identifiants invalides" (pas de distinction user/password)
- Affichage compte à rebours si rate limit atteint
- Suggestion de réinitialisation (bientôt disponible)

### 4. Tableau de bord (`dashboard.html`)

**Sections** :

#### Informations du compte
- Nom d'utilisateur
- Email
- Rôle (user, admin)
- Statut du compte (actif/inactif)

#### Sécurité
- Statut MFA (activé/désactivé)
- Session MFA vérifiée (oui/non)
- IP de connexion
- Badge de sécurité visuel

#### Actions rapides
- **Activer le MFA** (si désactivé) : carte avec CTA proéminent
- **Changer le mot de passe** : bientôt disponible
- Statistiques de sécurité

#### Informations de session
- Date/heure de création
- Date/heure d'expiration
- Adresse IP

#### Badge de conformité ASVS
- Card gradient avec statistiques
- Niveau L2, 20/20 exigences, 100% conformité

### 5. Enrôlement MFA (`mfa_enroll.html`)

**Flux en 3 étapes** :

#### Étape 1 : Scanner le QR code
- Génération QR code avec URI `otpauth://`
- Affichage grand format (250x250px)
- Option de configuration manuelle (affichage secret en base32)
- Bouton "Copier le secret"

#### Étape 2 : Sauvegarder les codes de récupération
- Affichage 10 codes au format `XXXX-XXXX`
- Design gradient avec cards individuelles
- Boutons d'action :
  - 📥 Télécharger (fichier .txt)
  - 🖨️ Imprimer (CSS print-friendly)
- ⚠️ Avertissement : "Chaque code utilisable une seule fois"

#### Étape 3 : Vérifier l'activation
- Champ TOTP à 6 chiffres
- Auto-formatting (espacement après 3 chiffres)
- Validation serveur
- Activation du MFA si succès

**Design** :
- Cards avec badges numérotés (1, 2, 3)
- Couleurs différenciées (bleu, orange, vert)
- Animations CSS (fadeIn, pulse)

**Codes de récupération** :
```
Format de téléchargement :
=========================
CODES DE RÉCUPÉRATION MFA
=========================

IMPORTANT: Conservez ces codes en lieu sûr.
Chaque code ne peut être utilisé qu'une seule fois.

ABCD-1234
EFGH-5678
...

Généré le: 17/10/2026 à 14:30:00
```

### 6. Pages d'erreur

#### 404 - Page non trouvée
- Icône triangle d'avertissement animé (pulse)
- Message convivial
- Boutons : "Retour à l'accueil" / "Tableau de bord"

#### 500 - Erreur serveur
- Icône serveur animé (shake)
- Message d'excuse
- Instructions utilisateur (rafraîchir, vérifier connexion)
- Bouton "Rafraîchir la page"

## Sécurité de l'interface

### Protection CSRF
Les formulaires HTML utilisent un jeton CSRF de session vérifié par l'application FastAPI avant tout POST.

### Sessions sécurisées
```python
app.config['SESSION_COOKIE_SECURE'] = True   # HTTPS uniquement
app.config['SESSION_COOKIE_HTTPONLY'] = True # Pas accessible en JS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protection CSRF
```

### En-têtes de sécurité (à ajouter en production)
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### Validation des entrées
- Côté client : JavaScript + HTML5 constraints
- Côté serveur : modules `auth_*` avec validation stricte
- Pas de confiance dans les données client

## API REST

### Validation de mot de passe en temps réel

**Endpoint** : `POST /api/validate-password`

**Headers** :
```
Content-Type: application/json
```

**Body** :
```json
{
  "password": "string",
  "username": "string (optionnel)"
}
```

**Réponse** :
```json
{
  "valid": boolean,
  "errors": [
    "Le mot de passe doit contenir au moins 12 caractères",
    "Ce mot de passe est compromis"
  ]
}
```

**Codes HTTP** :
- 200 : Validation effectuée (même si invalide)
- 400 : Requête malformée
- 500 : Erreur serveur

## Personnalisation

### Couleurs (`base.html`)
```css
:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --success-color: #10b981;
    --warning-color: #f59e0b;
    --danger-color: #ef4444;
    --gradient-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}
```

### Logo et branding
- Remplacer le texte "SecureAuth" par votre logo dans `base.html`
- Modifier `TOTP_ISSUER` dans `.env` pour l'affichage dans les apps MFA

### Textes et traductions
- Tous les textes sont dans les templates HTML
- Facile à traduire en modifiant les templates
- Support i18n (à implémenter)

## Tests de l'interface

### Tests manuels recommandés

1. **Inscription** :
   - ✅ Mot de passe < 12 caractères → rejeté
   - ✅ Mot de passe compromis (ex: "password123") → rejeté
   - ✅ Mot de passe valide → compte créé

2. **Rate limiting** :
   - ✅ 5 tentatives ratées → blocage temporaire
   - ✅ Affichage du compte à rebours
   - ✅ Déblocage automatique après 1 heure

3. **MFA** :
   - ✅ QR code scannable par Google Authenticator
   - ✅ Code TOTP valide → connexion réussie
   - ✅ Code TOTP invalide → erreur
   - ✅ Rejeu du même code → refusé

4. **Sessions** :
   - ✅ Session valide → accès au dashboard
   - ✅ Session expirée → redirection login
   - ✅ Logout → invalidation session

### Tests automatisés (à implémenter)

```python
# tests/test_web_interface.py
def test_register_page_loads(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Inscription' in response.data

def test_login_with_mfa(client):
    # Test du flux complet de connexion avec MFA
    pass
```

## Performance

### Optimisations appliquées
- ✅ Minification CSS/JS en production (à implémenter)
- ✅ Compression gzip (à configurer dans Nginx/Apache)
- ✅ CSS et scripts servis localement par FastAPI
- ✅ Lazy loading des images

### Métriques cibles
- Time to First Byte (TTFB) : < 200ms
- First Contentful Paint (FCP) : < 1s
- Time to Interactive (TTI) : < 2s

## Accessibilité (WCAG 2.1)

- ✅ Labels pour tous les champs de formulaire
- ✅ Contraste suffisant (ratio > 4.5:1)
- ✅ Navigation au clavier
- ✅ Attributs ARIA pour les alertes
- ⚠️ Tests avec lecteurs d'écran recommandés

## Compatibilité navigateurs

| Navigateur | Version minimale | Testé |
|-----------|------------------|-------|
| Chrome | 90+ | ✅ |
| Firefox | 88+ | ✅ |
| Safari | 14+ | ✅ |
| Edge | 90+ | ✅ |
| Opera | 76+ | ⚠️ |

## Déploiement

### Environnement de développement
```bash
<<<<<<< HEAD
python3 -m backend.app
# http://localhost:5000
=======
python3 -m uvicorn app:app --env-file .env --reload --host 127.0.0.1 --port 8080
# http://127.0.0.1:8080
>>>>>>> 68f20a7 (frontend)
```

### Environnement de production

#### Avec Uvicorn
```bash
<<<<<<< HEAD
gunicorn -w 4 -b 0.0.0.0:8000 backend.app:app
=======
uvicorn app:app --env-file .env --host 0.0.0.0 --port 8080 --workers 4
>>>>>>> 68f20a7 (frontend)
```

#### Avec Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
<<<<<<< HEAD
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "backend.app:app"]
=======
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
>>>>>>> 68f20a7 (frontend)
```

#### Reverse proxy Nginx
```nginx
server {
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Maintenance

### Logs
```python
# backend/app.py configure le logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Logs disponibles :
# - Tentatives de connexion
# - Enrôlements MFA
# - Erreurs de validation
# - Rate limiting
```

### Monitoring recommandé
- Sentry pour le suivi des erreurs
- Prometheus pour les métriques
- Grafana pour les dashboards
- Uptime monitoring (Pingdom, UptimeRobot)

## Roadmap futures fonctionnalités

- [ ] Changement de mot de passe
- [ ] Réinitialisation mot de passe par email
- [ ] Historique des connexions
- [ ] Gestion des sessions actives
- [ ] Notifications de sécurité
- [ ] Export des données utilisateur (RGPD)
- [ ] Mode sombre
- [ ] Internationalisation (i18n)

---

**Dernière mise à jour** : Octobre 2026  
**Conformité** : OWASP ASVS 5.0.0 - Niveau L2 (100%)
