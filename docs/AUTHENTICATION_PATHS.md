<<<<<<< HEAD
# Voies d'Authentification (Authentication Paths) & Sécurité ASVS 5.0.0 V6.3 / V6.4
# ASVS 5.0.0 — V6.3 et V6.4 (récupération et cycle de vie)

Ce document répertorie et documente l'ensemble des voies d'authentification disponibles dans l'application, les mécanismes de protection contre les attaques par force brute (6.3.1), l'absence de comptes par défaut (6.3.2), la gestion du second facteur TOTP (6.3.3), les alertes de sécurité (6.3.5 & 6.3.7), la non-utilisation de l'e-mail comme facteur (6.3.6) et les mécanismes anti-énumération (6.3.8).

---

## 1. Vue d'ensemble des flux d'authentification

L'application expose les mécanismes d'authentification suivants :
1. **Inscription de compte** (`backend/auth_register.py:register_user`)
2. **Authentification principale** (`backend/auth_login.py:authenticate_user`)
3. **Double facteur d'authentification (MFA TOTP)** (`backend/auth_mfa.py:verify_totp_code`, `verify_recovery_code`)
4. **Mise à jour des identifiants** (`backend/auth_register.py:change_password`, `change_email`, `change_username`)
5. **Initialisation du compte administrateur** (`backend/create_admin.py:create_admin`)
6. **Demande de réinitialisation du mot de passe** (`POST /password-reset`)
7. **Finalisation de réinitialisation** (`POST /password-reset/confirm`)
8. **Réinitialisation déclenchée par admin** (`POST /admin/users/<user_id>/password-reset`)
9. **Récupération MFA** (`POST /mfa/recovery/request`, puis `/mfa/recovery/confirm`)

Toutes les voies d'accès à la base de données s'exécutent exclusivement via l'ORM SQLAlchemy (`backend/models.py`), sans aucune requête SQL brute.

---

## 2. Inventaire des points d'entrée et contrôles associés

### 2.1 Inscription (`/register` - POST)
- **Fonction métier** : `auth_register.register_user(username, email, password)`
- **Paramètres requis** : `username` (alphanumérique + `_`, 3-30 car.), `email` (conforme RFC), `password` (12-128 car.).
- **Vérifications de sécurité** :
  - Longueur (12 à 128 caractères).
  - Mot de passe != nom d'utilisateur.
  - Absence de mots contextuels applicatifs (`backend/contextual_words.txt`).
  - Absence du mot de passe dans la liste des mots de passe courants (`backend/common_passwords.txt`).
  - Vérification HIBP k-anonymity avec padding.
  - Hachage Argon2id (`t=3, m=65536, p=4`).
- **Anti-énumération (6.3.8)** :
  - Message unifié identique que le nom d'utilisateur ou l'email soit déjà utilisé : `"Ce nom d'utilisateur ou cette adresse email est déjà utilisé"`.
  - En production avec canal d'email activé, schéma standard de confirmation neutre.

### 2.2 Connexion (`/login` - POST)
- **Fonction métier** : `auth_login.authenticate_user(username, password, ip_address, totp_code, recovery_code, user_agent)`
- **Contrôles de sécurité (6.3.1, 6.3.8)** :
  - **Rate Limiting multi-niveaux (6.3.1)** :
    - *Par IP* : 20 tentatives max sur 15 min -> verrouillage de 30 min.
    - *Par couple (username, IP)* : 5 tentatives max sur 10 min -> verrouillage de 15 min.
    - *Par username seul* : seuil élevé (50 tentatives sur 1 heure) avec délai progressif (backoff) pour ralentir les attaques distribuées sans provoquer de déni de service (DoS) sur le compte légitime.
    - *Seuls les échecs* sont comptabilisés.
    - *Messages de blocage unifiés* : `"Trop de tentatives de connexion. Veuillez réessayer plus tard"` (identique que le compte existe ou non).
  - **Protection Timing Attack (6.3.8)** :
    - Si l'utilisateur n'existe pas ou est inactif, une vérification Argon2id factice (`_get_dummy_hash()`) est systématiquement exécutée avec les mêmes paramètres pour garantir un temps de réponse équivalent.
    - Code HTTP et message d'erreur unifiés : `"Nom d'utilisateur ou mot de passe incorrect"`.

### 2.3 Double facteur MFA TOTP (RFC 6238)
- **Fonctions métier** :
  - Enrôlement : `auth_mfa.enroll_mfa(user_id, username)` -> secret CSPRNG 256 bits, QR Code standard.
  - Validation de l'enrôlement : `auth_mfa.validate_mfa_enrollment(user_id, code)` -> validé par un premier code avant activation.
  - Vérification TOTP : `auth_mfa.verify_totp_code(secret, code, user_id)` -> validité 30s, anti-rejeu strict via la table ORM `totp_used_codes`.
  - Codes de secours : `auth_mfa.generate_recovery_codes()`, `auth_mfa.verify_recovery_code(user_id, code)` -> 10 codes uniques générés par CSPRNG, à usage unique, hachés avec sel via Argon2id (`MfaRecoveryCode`).
- **Règles strictes (6.3.3, 6.3.6)** :
  - Aucune session ou jeton n'est émis avant la validation réussie du TOTP ou du code de récupération.
  - L'e-mail n'est **JAMAIS** utilisé comme facteur d'authentification (aucun code OTP par e-mail, aucun lien magique).

### 2.4 Mise à jour des identifiants
- **Changement de mot de passe** : `auth_register.change_password(user_id, current_password, new_password, ip_address)`
  - Vérification obligatoire du mot de passe actuel côté serveur.
  - Nouveau mot de passe soumis à toutes les validations ASVS 6.2 et différent de l'actuel.
  - Soumis au même rate limiting que le login (protection contre la force brute du mot de passe actuel).
  - Notification de sécurité immédiate envoyée à l'adresse e-mail de l'utilisateur (**sans mot de passe**).
- **Changement d'adresse e-mail** : `auth_register.change_email(user_id, new_email, current_password, ip_address)`
  - Vérification du mot de passe actuel.
  - Validation du format du nouvel e-mail.
  - Notification envoyée à l'**ancienne ET à la nouvelle adresse e-mail** (ASVS 6.3.7).
- **Changement de nom d'utilisateur** : `auth_register.change_username(user_id, new_username, current_password, ip_address)`
  - Notification envoyée à l'adresse e-mail de l'utilisateur.

### 2.5 Création d'administrateur initial (`backend/create_admin.py`)
- Commande CLI dédiée : `python backend/create_admin.py --username admin_ops --email admin@domain.com`
- Aucun compte par défaut dans le code, les tests ou les migrations (ASVS 6.3.2).
- Le mot de passe est saisi par l'opérateur et doit respecter tous les critères ASVS 6.2.

---

## 3. Système d'alerte et de notification des tentatives suspectes (6.3.5 & 6.3.7)

L'application intègre une abstraction de notification (`backend/notifications.py:BaseNotificationService`) avec :
- Une implémentation de production `EmailNotificationService` (SMTP avec STARTTLS / SSL).
- Une implémentation de développement/journalisation `DevLogNotificationService`.

### Déclencheurs d'alertes suspectes (6.3.5) :
1. **Connexion depuis un nouvel appareil ou une nouvelle adresse IP** :
   - Empreinte (IP + User-Agent) enregistrée dans la table ORM `user_devices`.
   - Si l'IP ou l'appareil est inconnu pour cet utilisateur, une notification d'alerte est expédiée.
2. **Connexion réussie après plusieurs échecs consécutifs** :
   - Seuil configurable (`SUSPICIOUS_FAILED_ATTEMPTS_THRESHOLD = 3`).
   - Alerte transmise à l'utilisateur indiquant l'adresse IP et le nombre de tentatives.
3. **Authentification partiellement réussie (mot de passe correct, mais échec MFA)** :
   - Alerte critique envoyée immédiatement à l'utilisateur pour l'avertir que son mot de passe est potentiellement compromis, bien que le MFA ait bloqué l'accès.
4. **Reconnexion après longue inactivité** :
   - Durée configurable (`LOGIN_INACTIVITY_THRESHOLD = timedelta(days=30)`).
   - Horodatage suivi via `User.last_login_at`.

### Propriétés de sécurité des notifications :
- **Aucun secret exposé** : ni mot de passe en clair, ni secret TOTP, ni token de session.
- **Fail-open sécurisé** : une indisponibilité temporaire du serveur SMTP est journalisée en erreur, mais ne bloque jamais l'accès de l'utilisateur légitime.
- **Aucune fuite à un tiers** : alertes envoyées strictement à l'adresse du propriétaire du compte.

---

## 4. Configuration requise en production

Pour activer l'envoi effectif d'e-mails en production, définir les variables d'environnement suivantes :
```bash
NOTIFICATION_BACKEND=email
SMTP_HOST=smtp.votre-domaine.com
SMTP_PORT=587
SMTP_USER=votre_utilisateur_smtp
SMTP_PASSWORD=votre_mot_de_passe_smtp
SMTP_USE_TLS=true
SMTP_USE_SSL=false
NOTIFICATION_EMAIL_FROM=securite@votre-domaine.com
```
En l'absence de ces variables, le backend par défaut (`NOTIFICATION_BACKEND=dev`) journalise les notifications avec niveau WARNING dans les logs de l'application sans bloquer le système.

## 5. Récupération des authentificateurs (ASVS V6.4)

- Les comptes sont inscrits avec un mot de passe choisi par la personne ; aucun mot de passe initial n'est généré.
- La demande de reset répond toujours avec le même message HTTP 200. Les jetons ont 256 bits aléatoires, sont stockés hachés, expirent après `PASSWORD_RESET_TOKEN_TTL` (20 minutes par défaut), sont à usage unique et remplacent les demandes précédentes.
- La finalisation exige le TOTP ou un code de récupération lorsque MFA est actif, un nouveau mot de passe validé par `validate_password`, et invalide toutes les sessions.
- La récupération MFA n'est accessible qu'à une session ayant déjà passé le MFA (le code de récupération sert à se connecter en cas de perte du TOTP), et demande aussi le mot de passe courant et un lien à usage unique envoyé à l'adresse enregistrée. Après confirmation, les anciens facteurs sont supprimés, les sessions invalidées et le prochain accès est limité au réenrôlement MFA.
- Un administrateur peut uniquement déclencher le reset d'un compte via une route protégée côté serveur. Le jeton est transmis à l'utilisateur, jamais retourné à l'administrateur.
- L'inscription courante prouve la possession de l'adresse e-mail et le choix d'un mot de passe. L'enrôlement MFA exige une session authentifiée par ces éléments ; la récupération MFA exige cette session (donc le MFA existant, TOTP ou code de récupération), puis mot de passe et boîte e-mail.

En production, configurer `NOTIFICATION_BACKEND=email`, un SMTP avec STARTTLS/SSL et `PASSWORD_RESET_URL_BASE` / `APP_PUBLIC_BASE_URL` vers le domaine HTTPS public. Le backend `dev` journalise le contenu et n'expédie pas réellement le message ; les flux de récupération ne sont alors pas opérationnels pour les utilisateurs distants.
=======
# Authentication paths and backend controls

## Password login

`auth_login.authenticate_user` applies the IP, account/IP, and account-wide
limits before looking up the user. The stored Argon2id password hash is
verified with `auth_register.verify_password`. Missing users and wrong
passwords receive the same public error. If MFA is enabled, password login
does not issue a session until the TOTP or a recovery code is verified.

## Sessions and logout

Successful authentication creates a 256-bit random token with
`secrets.token_hex`, stores it in the MySQL `sessions` table, and sets its
expiry. `validate_session` rejects expired, revoked, or inactive-user sessions.
`logout_user` invalidates the stored session; its token is not written to logs.

## Backend authorization

Backend operations that act on a user's private account data must call
`require_valid_session(session_token, user_id)` and use the returned session
data as the authorized identity. It raises `AccessDeniedError` when the token
is missing, expired, revoked, inactive, or belongs to another user. MFA
enrollment and enrollment validation enforce this in `auth_mfa.py`; this
control has no Flask dependency. Flask routes may add their own presentation
layer checks, but those checks do not replace backend authorization.

## Rate limits

The current defaults are in `config.py`: 20 failed attempts per IP in 15
minutes with a 30-minute IP block; 5 per account/IP in 10 minutes with a
15-minute block; and a 50-attempt account threshold in one hour with
progressive delay. Counts are queried from MySQL within the configured
windows. The rate-limit check currently fails open if MySQL is unavailable;
operators should monitor database availability and treat this as a remaining
hardening limitation.

## Verification

P2 integration tests use MySQL only. Set `TEST_DB_NAME` to a pre-created,
dedicated test database whose name starts with `test_`; tests skip MySQL cases
when it is unset and refuse names without that prefix. See the P2 section in
`README.md` for environment variables and commands. The suite does not create
or delete databases and does not inspect or alter production accounts.
>>>>>>> 68f20a7 (frontend)
