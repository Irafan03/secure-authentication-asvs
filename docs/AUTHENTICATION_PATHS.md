# Voies d'Authentification (Authentication Paths)
# ASVS 5.0.0 — V6.3.4 & V6.1.3 (Niveau 2)

Ce document répertorie et documente l'ensemble des voies et points d'entrée d'authentification disponibles dans l'application, conformément aux exigences ASVS 5.0.0 V6.3.4 et V6.1.3.

---

## 1. Vue d'ensemble des flux d'authentification

L'application expose les mécanismes d'authentification suivants :
1. **Création de compte / Inscription** (`auth_register.py`)
2. **Authentification principale / Connexion** (`auth_login.py`)
3. **Double facteur d'authentification / MFA TOTP** (`auth_mfa.py`)
4. **Changement de mot de passe** (`auth_register.py`)

Toutes les voies respectent les contrôles de sécurité :
- Pas de règles de composition arbitraires (ASVS 6.2.5).
- Longueur minimale de 12 caractères et maximale de 128 caractères (ASVS 6.2.1, 6.2.2).
- Vérification contre les mots de passe compromis (liste locale et HIBP k-anonymity) (ASVS 6.2.4, 6.2.12).
- Rejet des mots contextuels liés à l'application (ASVS 6.2.11).
- Hachage résistant via Argon2id (ASVS 2.4).
- Protection contre les attaques par force brute (délai progressif et rate limiting sans verrouillage DoS) (ASVS 6.3.1).
- Messages d'erreur génériques pour prévenir l'énumération (ASVS 6.3.8).

---

## 2. Inventaire des points d'entrée

### 2.1 Inscription (`/register` - POST)
- **Fonction métier** : `auth_register.register_user(username, email, password)`
- **Paramètres requis** : `username` (alphanumérique + `_`, 3-30 car.), `email` (conforme RFC), `password` (12-128 car.).
- **Vérifications** :
  - Longueur (12 à 128 caractères).
  - Mot de passe != nom d'utilisateur.
  - Absence de mots contextuels (`contextual_words.txt`).
  - Absence du mot de passe dans la liste des mots de passe courants (`common_passwords.txt`).
  - Vérification HIBP k-anonymity (`Add-Padding: true`).
- **Erreurs** : Message générique unifié si utilisateur ou email déjà existant (`Ce nom d'utilisateur ou cette adresse email est déjà utilisé`).

### 2.2 Connexion (`/login` - POST)
- **Fonction métier** : `auth_login.login_user(identifier, password, ip_address)`
- **Paramètres requis** : `identifier` (username ou email), `password`, `ip_address`.
- **Mécanismes de protection** :
  - Rate limiting basé sur l'adresse IP et l'identifiant.
  - Délai progressif sans verrouillage de compte (anti-déni de service).
  - Temps de réponse constant contre les attaques par canal auxiliaire (timing attacks).
  - Si l'utilisateur a activé le 2FA, émission d'un token temporaire pour l'étape MFA.

### 2.3 Double facteur MFA TOTP (`/mfa/verify`, `/mfa/recovery` - POST)
- **Fonctions métier** :
  - Configuration : `auth_mfa.generate_totp_secret()`, `auth_mfa.get_totp_uri()`
  - Vérification TOTP : `auth_mfa.verify_totp(user_id, code)` (fenêtre de validité stricte, anti-rejeu)
  - Codes de secours : `auth_mfa.generate_recovery_codes()`, `auth_mfa.use_recovery_code(user_id, code)` (usage unique, hachés en base).

### 2.4 Changement de mot de passe (`/change-password` - POST)
- **Fonction métier** : `auth_register.change_password(user_id, current_password, new_password)`
- **Paramètres requis** : `user_id`, `current_password`, `new_password`.
- **Règles appliquées** :
  - Vérification côté serveur du mot de passe actuel.
  - Vérification que le nouveau mot de passe est différent de l'ancien.
  - Validation complète du nouveau mot de passe (mêmes exigences qu'à l'inscription).
  - Aucune exigence de réinitialisation périodique forcée (ASVS 6.4.2).

---

## 3. Absence de voies alternatives non sécurisées

- Aucun compte ou mot de passe par défaut n'est pré-configuré (ASVS 6.3.2).
- Aucune question secrète ni réinitialisation de mot de passe non sécurisée par email clair ou tokens faibles (ASVS 6.4.2).
- Aucune API d'administration non documentée ou voie dérobée.
