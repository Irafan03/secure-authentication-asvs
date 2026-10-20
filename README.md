# SecureAuth ASVS

Application d'authentification avec une interface React/TypeScript et une API JSON Flask. L'ancienne interface HTML/Jinja a été retirée du parcours applicatif.

## Fonctionnalités

- Création de compte et connexion avec réponses d'erreur génériques et limitation des tentatives.
- Sessions opaques dans un cookie `HttpOnly`, `SameSite=Lax`; le token n'est jamais envoyé au JavaScript.
- MFA TOTP avec QR code, codes de récupération à usage unique, validation à la connexion et désactivation protégée.
- Changement et réinitialisation du mot de passe, avec validation serveur et vérification MFA lorsque le compte l'exige.
- Protection des routes React et rechargement de la session depuis l'API.

## Prérequis

- Python 3.11 ou plus récent
- Node.js 20 ou plus récent
- MySQL 8

## Installation

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
npm ci --prefix frontend
cp .env.example .env
```

Configurez `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` et `DB_PASSWORD` dans `.env` pour une base MySQL locale. Remplacez également `SESSION_SECRET_KEY` par une valeur aléatoire. Les tables sont initialisées au premier appel API.

### Envoi des e-mails de récupération

Pour tester le parcours en local, démarrez d'abord la boîte de réception Mailpit :

```sh
docker compose -f docker-compose.mailpit.yml up -d
```

Dans `.env`, configurez `NOTIFICATION_BACKEND=email`, `SMTP_HOST=127.0.0.1`, `SMTP_PORT=1025`, `SMTP_USE_TLS=false`, `SMTP_USE_SSL=false`, `SMTP_USER=` et `SMTP_PASSWORD=`. Après une demande de réinitialisation, ouvrez **http://127.0.0.1:8025** pour consulter l'e-mail de test et suivre son lien. Mailpit garde les messages uniquement dans cette boîte locale : aucun courriel n'est envoyé à l'adresse réelle.

Pour envoyer réellement les liens aux utilisateurs, renseignez dans `.env` un fournisseur SMTP avec `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_USE_TLS` et `NOTIFICATION_EMAIL_FROM`, puis définissez `NOTIFICATION_BACKEND=email`. Avec Gmail, utilisez `smtp.gmail.com:587`, TLS et un **mot de passe d'application** Google (pas le mot de passe habituel du compte). `APP_PUBLIC_BASE_URL` doit correspondre à l'adresse utilisée dans le navigateur. Redémarrez `./start.sh` après toute modification de `.env`.

Sans configuration SMTP, les demandes restent volontairement génériques pour ne pas révéler si une adresse existe, mais aucun e-mail n'est délivré. En développement, le journal indique qu'une notification n'a pas été envoyée sans écrire le lien sensible dans les logs.

Si la base et l'utilisateur n'existent pas encore, créez-les dans MySQL avec un mot de passe choisi par vous, puis reportez ce même mot de passe dans `.env` :

```sql
CREATE DATABASE secure_auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'secure_auth_user'@'localhost' IDENTIFIED BY 'choisir-un-mot-de-passe-fort';
GRANT ALL PRIVILEGES ON secure_auth_db.* TO 'secure_auth_user'@'localhost';
```

## Lancement

```sh
./start.sh
```

Interface React : **http://127.0.0.1:5173**

API Flask : **http://127.0.0.1:5000**

Pour lancer les serveurs séparément :

```sh
./.venv/bin/python -m backend.app
cd frontend && npm run dev
```

Pour compiler une version statique React que Flask sert sous la même origine :

```sh
npm run build --prefix frontend
```

## API d'authentification

| Méthode | Route | Fonction |
|---|---|---|
| `POST` | `/register` | Inscription JSON |
| `POST` | `/login` | Connexion, TOTP ou code de récupération |
| `GET` | `/api/auth/session` | Session courante |
| `POST` | `/api/auth/logout` | Déconnexion et invalidation du token |
| `POST` | `/api/validate-password` | Validation serveur du mot de passe |
| `POST` | `/api/account/password` | Changement du mot de passe |
| `POST` | `/api/account/mfa/enrollment` | Démarrer l'enrôlement TOTP |
| `POST` | `/api/account/mfa/enrollment/confirm` | Confirmer le code et activer la MFA |
| `POST` | `/api/account/mfa/disable` | Désactiver la MFA avec mot de passe et facteur valide |
| `POST` | `/password-reset` | Demander un lien de réinitialisation |
| `POST` | `/password-reset/confirm` | Confirmer la réinitialisation |
| `POST` | `/mfa/recovery/request` | Demander une récupération MFA |
| `POST` | `/mfa/recovery/confirm` | Confirmer une récupération MFA |

## Vérifications

```sh
npm test --prefix frontend
npm run build --prefix frontend
npm run lint --prefix frontend
./.venv/bin/python -m pytest tests/test_api_contracts.py -q
```

Les comptes et opérations d'authentification nécessitent une base MySQL configurée. Les tests d'API isolent les fonctions métier pour vérifier les contrats HTTP sans modifier de comptes réels.
