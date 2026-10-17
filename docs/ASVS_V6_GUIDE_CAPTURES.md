# Guide de captures — ASVS 5.0.0 V6.2, V6.3 et V6.4

Ce guide sépare les preuves présentes dans le dépôt des manipulations qui restent à effectuer. Les noms de capture sont des propositions. Les commandes d'exécution n'ont pas été lancées sauf mention **RÉEL**. Ne pas présenter un résultat attendu comme une preuve obtenue.

**Règle de cadrage :** chaque fenêtre de code proposée ci-dessous fait 15 à 25 lignes inclusives au plus. Si une fonction est plus longue, elle est découpée en captures a/b. Les captures de test sont également limitées à de courts extraits (nom du test et assertions principales). Masquer tout mot de passe, jeton, cookie, hash complet, adresse e-mail personnelle, valeur de `.env`, QR TOTP et secret MFA.

## 1. Synthèse

| Exigence | Statut | Capture code | Capture test | Capture exécution | Capture données |
|---|---|---:|---:|---:|---:|
| 6.2.1 | ✅ Respectée (12 min.; 15 recommandé) | ✔ | ✔ | ✔ | ✔ |
| 6.2.2 | ⚠️ Partielle (fonction métier, pas de route web) | ✔ | ✔ | ✔ | — |
| 6.2.3 | ⚠️ Partielle (fonction métier, pas de route web) | ✔ | ✔ | ✔ | — |
| 6.2.4 | ❌ Non respectée (1 970 entrées uniques, 199 ≥ 12 caractères) | ✔ | ✔ | ✔ | ✔ |
| 6.2.5 | ✅ Respectée dans la validation backend | ✔ | ✔ | ✔ | — |
| 6.2.6 | ❓ Non vérifiable (pas de templates frontend) | ✔ | — | ✔ | — |
| 6.2.7 | ❓ Non vérifiable (pas de formulaire frontend d'inscription/connexion) | ✔ | — | ✔ | — |
| 6.2.8 | ✅ Respectée dans le hachage/vérification | ✔ | ✔ | ✔ | — |
| 6.2.9 | ✅ Respectée (maximum 128) | ✔ | ✔ | ✔ | ✔ |
| 6.2.10 | ✅ Respectée dans le code relu (pas de rotation périodique) | ✔ | — | ✔ | ✔ |
| 6.2.11 | ✅ Respectée dans la validation | ✔ | ✔ | ✔ | ✔ |
| 6.2.12 | ⚠️ Partielle (`HIBP_FAIL_OPEN=True`) | ✔ | ✔ | ✔ | ✔ |
| 6.3.1 | ⚠️ Partielle (tests DB non exécutables ici) | ✔ | ✔ | ✔ | ✔ |
| 6.3.2 | ✅ Respectée dans le code relu (pas de compte précréé) | ✔ | ✔ | ✔ | — |
| 6.3.3 | ⚠️ Partielle (MFA conditionnel, pas imposé à tous; route ne transmet pas le code secours) | ✔ | ✔ | ✔ | ✔ |
| 6.3.4 | ⚠️ Partielle (voies backend documentées; changement de mot de passe sans route web) | ✔ | ✔ | ✔ | ✔ |
| 6.3.5 | ⚠️ Partielle (événements déclenchés, mail dev journalisé) | ✔ | ✔ | ✔ | ✔ |
| 6.3.6 | ✅ Respectée pour l'authentification primaire/MFA | ✔ | ✔ | ✔ | — |
| 6.3.7 | ⚠️ Partielle (appels présents, mail dev journalisé) | ✔ | ✔ | ✔ | ✔ |
| 6.3.8 | ⚠️ Partielle (messages backend génériques; différence temporelle reset et routes HTML non validées) | ✔ | ✔ | ✔ | ✔ |
| 6.4.1 | ✅ Respectée pour les jetons de récupération | ✔ | ✔ | ✔ | ✔ |
| 6.4.2 | ✅ Respectée dans le code recherché | ✔ | — | ✔ | — |
| 6.4.3 | ⚠️ Partielle tant que l'envoi SMTP n'est pas établi | ✔ | ✔ | ✔ | ✔ |
| 6.4.4 | ⚠️ Partielle (lien mail requis; preuve liée au facteur/session conservé) | ✔ | — | ✔ | ✔ |
| 6.4.5 | ➖ Non applicable (aucun authentificateur applicatif à expiration périodique) | ✔ | — | ✔ | — |
| 6.4.6 | ⚠️ Partielle tant que l'envoi SMTP n'est pas établi | ✔ | ✔ | ✔ | ✔ |

## 2. Phase 0 — Découverte

- Arborescence applicative courte : modules Python à la racine, `docs/`, `tests/`; Flask (`backend/app.py`), SQLAlchemy (`backend/models.py`) et MySQL. L'ancien chemin `mysql.connector` demeure dans `backend/database.py` et des branches de compatibilité de certains modules.
- Authentification : `backend/app.py`, `backend/auth_register.py`, `backend/auth_login.py`, `backend/auth_mfa.py`, `backend/password_recovery.py`, `backend/models.py`, `backend/notifications.py`, `backend/config.py`, `backend/create_admin.py`. Seuils et durées : `backend/config.py`. Modèles ORM : `backend/models.py`. Aucun dossier de templates HTML/Jinja ni outil de migration trouvé. `docs/AUTHENTICATION_PATHS.md` est le document de sécurité existant.
- Routes actuellement enregistrées dans `backend/app.py` : `GET /` → `index`; `GET|POST /register` → `register`; `GET|POST /login` → `login`; `GET /dashboard` → `dashboard`; `GET|POST /mfa/enroll` → `mfa_enroll`; `GET /logout` → `logout`; `POST /api/validate-password` → `api_validate_password`; `GET|POST /password-reset` → `password_reset_request`; `GET|POST /password-reset/confirm` → `password_reset_confirm`; `POST /admin/users/<user_id>/password-reset` → `admin_password_reset_request`; `POST /mfa/recovery/request` → `mfa_recovery_request`; `GET|POST /mfa/recovery/confirm` → `mfa_recovery_confirm`; `GET /test` → `test`.
- Tests : pytest; dossier `tests/`. Noms exacts détectés :
  - `tests/test_password_validation.py` : `test_6_2_1_password_min_12_chars`, `test_6_2_1_password_64_chars`, `test_6_2_1_password_128_chars`, `test_6_2_2_password_max_128_chars`, `test_6_2_5_no_composition_rules_lowercase_only`, `test_6_2_5_no_composition_rules_no_symbols`, `test_6_2_5_no_composition_rules_no_numbers`, `test_6_2_5_no_composition_rules_no_uppercase`, `test_6_2_3_password_not_truncated`, `test_6_2_3_password_not_same_as_username`, `test_password_valid_examples`.
  - `tests/test_register.py` : `test_valid_usernames`, `test_invalid_usernames`, `test_valid_emails`, `test_invalid_emails`, `test_password_length_validation`, `test_password_no_composition_rules`, `test_password_username_validation`, `test_common_passwords_validation`, `test_valid_passwords`, `test_password_hashing`, `test_password_verification`, `test_hash_uniqueness`, `test_successful_registration`, `test_registration_with_invalid_data`, `test_successful_password_change`, `test_password_change_with_wrong_current`, `test_load_common_passwords`.
  - `tests/test_password_change.py` : `test_password_change_validation_rules`, `test_same_password_rejection`, `test_successful_password_change`, `test_wrong_current_password`, `test_user_not_found`, `test_inactive_user`, `test_database_error_handling`, `test_maximum_length_password`, `test_unicode_password_support`, `test_username_similarity_check`, `test_full_password_change_workflow`, `test_concurrent_password_changes`.
  - `tests/test_asvs_level1.py` : `test_6_2_1_password_min_12_chars`, `test_6_2_1_password_64_chars`, `test_6_2_1_password_128_chars`, `test_6_2_2_password_max_128_chars`, `test_6_2_5_no_composition_rules`, `test_6_2_4_compromised_password_rejected`, `test_6_2_3_password_not_truncated`, `test_6_3_1_rate_limiting_by_ip`, `test_6_3_1_rate_limiting_no_account_lockout_dos`, `test_6_3_1_progressive_delay`, `test_6_3_8_timing_attack_protection`, `test_6_3_8_generic_error_messages`, `test_6_4_2_no_password_reset`, `test_6_3_2_no_default_accounts`.
  - `tests/test_asvs_level2.py` : `test_6_2_11_contextual_words_rejected`, `test_6_2_11_non_contextual_words_accepted`, `test_6_5_1_totp_secret_generation`, `test_6_5_1_totp_uri_generation`, `test_6_5_3_totp_verification`, `test_6_5_2_recovery_codes_generation`, `test_6_5_2_recovery_codes_unique`, `test_6_3_8_registration_generic_message`, `test_6_2_12_hibp_on_password_change`, `test_6_3_4_authentication_paths_documented`.
  - `tests/test_asvs_v6_3.py` : `test_6_3_1_no_account_lockout_dos_from_different_ip`, `test_6_3_1_progressive_delay_on_failures`, `test_6_3_1_only_failures_counted_for_lockout`, `test_6_3_1_uniform_lockout_message`, `test_6_3_2_no_default_accounts`, `test_6_3_2_create_admin_cli_requires_strong_password`, `test_6_3_3_cannot_login_without_mfa`, `test_6_3_3_totp_replay_rejected`, `test_6_3_3_recovery_code_single_use`, `test_6_3_4_no_bypass_and_password_change_rate_limited`, `test_6_3_5_suspicious_notifications`, `test_6_3_6_no_email_authentication_factor`, `test_6_3_7_credential_update_notifications`, `test_6_3_8_anti_enumeration_login`, `test_6_3_8_timing_attack_response_comparable`, `test_6_3_8_registration_response_generic`.
  - `tests/test_password_recovery.py` : `test_reset_request_is_neutral_and_stores_only_hash`, `test_reset_is_one_use_and_invalidates_sessions`, `test_reset_admin_metadata_does_not_return_secret`, `test_reset_does_not_bypass_enabled_mfa`.
- Le test ancien `test_6_4_2_no_password_reset` teste une absence de fonction `auth_login.reset_password`; son nom/commentaire ne décrit plus l'état actuel et ne prouve pas 6.4.2.

### Mesures de tests réellement lancées

- `.venv/bin/pytest -q` : **51 passed, 3 failed, 30 errors**. Les erreurs de setup tentent MySQL `localhost:3306`, inaccessible dans cet environnement. Les trois échecs concernent le refus attendu d'un mot de passe par HIBP alors que DNS/réseau vers `api.pwnedpasswords.com` échoue et que `HIBP_FAIL_OPEN=True` autorise le mode dégradé.
- `.venv/bin/pytest -q tests/test_password_recovery.py` exécuté pendant la préparation de ce guide : **4 passed**. Ne pas en déduire que SMTP, MySQL de production ou les routes Flask entières ont été intégrées.

## 3. Préparation commune

### Comptes et données de démonstration

Créer uniquement dans une base de test : (1) `demo_plain`, sans MFA; (2) `demo_mfa`, MFA activé avec TOTP et code secours de test; (3) `demo_admin`, rôle admin; (4) ne pas créer `demo_absent`. Ne jamais réutiliser un compte ou secret réel. Créer en plus des valeurs synthétiques de 64 et 128 caractères, un mot de passe contextuel (`MySecurePassword123`), un mot de passe courant, et un mot de passe connu comme fuité réservé aux tests. Les tests actuels montrent que le 128 est accepté par politique, mais une vérification HIBP peut faire échouer l'exemple quand le service répond.

### Services et démarrage

Le serveur réel exige une base MySQL compatible avec les variables `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`; ne pas afficher leurs valeurs. Pour vérifier la livraison de notification, définir sur un SMTP de test `NOTIFICATION_BACKEND=email`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_USE_TLS=true` (ou `SMTP_USE_SSL=true`), `NOTIFICATION_EMAIL_FROM`, `PASSWORD_RESET_URL_BASE=https://<hôte-test>/password-reset/confirm` et `APP_PUBLIC_BASE_URL=https://<hôte-test>`. La valeur par défaut du backend est `dev`: le contenu du message est journalisé, pas envoyé à une boîte.

Commandes de lancement (exécuter seulement depuis un terminal de test configuré) :

```bash
# Terminal DB : démarrer MySQL de test avec le gestionnaire local habituel.
# Terminal application :
source .venv/bin/activate
python backend/app.py
# Créer l'admin par saisie masquée (ne jamais passer --password dans l'historique du shell) :
python backend/create_admin.py --username demo_admin --email admin@example.test
```

L'application tente `init_db()` (ancien initialiseur MySQL) puis `init_db_orm()`. L'environnement courant n'a pas de MySQL joignable. Aucun frontend classique n'a été trouvé; les routes d'authentification ordinaires appellent des templates absents, alors que les formulaires V6.4 sont rendus directement dans `backend/app.py`.

### Inventaire des captures de code (fenêtres courtes)

| ID capture | Fichier | Lignes exactes à afficher | Portée (15–25 lignes max) |
|---|---|---:|---|
| K01 | `backend/auth_register.py` | 221–237 | Minimum/maximum et absence de composition |
| K02 | `backend/auth_register.py` | 237–254 | Mots contextuels, liste courante et vérification HIBP |
| K03 | `backend/auth_register.py` | 256–276 | Hachage Argon2id sans transformation |
| K04 | `backend/auth_register.py` | 278–298 | Vérification du mot de passe tel que reçu |
| K05 | `backend/auth_register.py` | 549–569 | Changement : utilisateur actif, rate limit, validation mot de passe courant |
| K06 | `backend/auth_register.py` | 572–591 | Différence ancien/nouveau, validation et mise à jour |
| K07 | `backend/auth_register.py` | 38–53 | Chargement de la liste courante |
| K08 | `backend/auth_register.py` | 83–103 | SHA-1 prefix k-anonymity HIBP et padding |
| K09 | `backend/config.py` | 14–18 | Longueurs 12 et 128 |
| K10 | `backend/config.py` | 43–52 | HIBP, mode fail-open et seuil déclaré 3000 |
| K11 | `backend/config.py` | 58–73 | Seuils IP, identifiant/IP, identifiant |
| K12a | `backend/auth_login.py` | 104–123 | Comptage et verrouillage IP |
| K12b | `backend/auth_login.py` | 124–148 | Comptage et verrouillage identifiant/IP |
| K12c | `backend/auth_login.py` | 150–167 | Comptage identifiant et délai progressif |
| K13 | `backend/auth_login.py` | 395–416 | Vérification de débit avant identification |
| K14a | `backend/auth_login.py` | 416–439 | Hash factice, message générique utilisateur absent/inactif |
| K14b | `backend/auth_login.py` | 467–489 | Demande et validation MFA avant session |
| K15 | `backend/create_admin.py` | 49–68 | Mot de passe choisi/validé et absence de création par défaut |
| K16 | `backend/auth_mfa.py` | 110–132 | Validation TOTP + anti-rejeu (recadrer les valeurs) |
| K17 | `backend/auth_mfa.py` | 218–240 | Vérification des codes de secours |
| K18a | `backend/notifications.py` | 45–64 | Alerte nouvel appareil et après échecs |
| K18b | `backend/notifications.py` | 65–83 | Notification d'échec MFA |
| K19a | `backend/auth_login.py` | 513–536 | Initialisation alertes et notification inactivité (début) |
| K19b | `backend/auth_login.py` | 529–548 | Retour après inactivité et appareil connu (début) |
| K19c | `backend/auth_login.py` | 546–565 | Nouvel appareil/IP et notification |
| K20a | `backend/notifications.py` | 98–117 | Notification password changed et début notification reset |
| K20b | `backend/notifications.py` | 119–138 | Notifications MFA et début notification email |
| K21 | `backend/auth_register.py` | 594–608 | Appel notification après changement de mot de passe |
| K37 | `backend/auth_register.py` | 655–673 | Changement d'email et notification anciennes/nouvelles adresses |
| K38 | `backend/auth_register.py` | 713–731 | Changement de username et notification |
| K22 | `backend/auth_login.py` | 33–55 | Hash factice et CSPRNG du jeton de session |
| K23 | `backend/models.py` | 50–71 | Modèles jeton reset et obligation de réenrôlement |
| K24 | `backend/password_recovery.py` | 21–43 | Création, hash, dates, initiateur, révocation/pruning |
| K25 | `backend/password_recovery.py` | 46–68 | Demande neutre, limitation, lookup ORM et travail factice |
| K26a | `backend/password_recovery.py` | 80–102 | Jeton valide, unique et expiration |
| K26b | `backend/password_recovery.py` | 103–115 | MFA obligatoire avant reset |
| K26c | `backend/password_recovery.py` | 116–137 | Nouveau mot de passe et sessions révoquées |
| K27 | `backend/password_recovery.py` | 161–185 | Récupération MFA, suppression facteurs et sessions |
| K28 | `backend/app.py` | 50–64 | Décorateurs d'accès et autorisation admin côté serveur |
| K29 | `backend/app.py` | 264–283 | Formulaire et endpoint de confirmation de reset |
| K30 | `backend/app.py` | 286–300 | Route admin et demande récupération MFA |
| K31 | `backend/app.py` | 303–323 | Confirmation récupération MFA protégée |
| K32 | `backend/config.py` | 110–116 | Durée session, TTL reset et URL publiques |
| K33 | `docs/AUTHENTICATION_PATHS.md` | 41–59 | Voies login et MFA documentées |
| K34 | `docs/AUTHENTICATION_PATHS.md` | 125–144 | Niveau de preuve/récupération et config mail |
| K35 | `backend/notifications.py` | 165–180 | Backend de développement = journalisation |
| K36 | `backend/notifications.py` | 218–240 | Envoi SMTP réel |

Les recherches d'absence (fiches 6.2.6, 6.2.7, 6.2.10, 6.3.2, 6.3.6 et 6.4.2/6.4.5) doivent être capturées dans le terminal avec commande et périmètre visibles; elles sont listées dans les fiches ci-dessous. Les seuls fichiers de sortie autorisés ici sont ce guide; ne sauvegarder aucune capture contenant des secrets.

## 4. Fiches des exigences

### V6.2 — Mots de passe

#### 6.2.1 — Longueur minimale

**Exigence** : 6.2.1, longueur minimale du mot de passe (8 minimum, 15 recommandé).
**Statut** : ✅ Respectée pour le minimum; politique actuelle 12, en dessous de la recommandation 15.

**A. Capture du CODE**

| N° | Fichier | Fonction ou classe | Lignes | Ce qui doit être visible | Nom conseillé |
|---|---|---|---:|---|---|
| K01 | `backend/auth_register.py` | `validate_password` | 221–237 | Vérification de longueur min/max, aucune règle de composition | `6_2_1_code_validation.png` |
| K09 | `backend/config.py` | constantes | 14–18 | Valeur 12 et maximum 128 | `6_2_1_config_minimum.png` |

**B. Capture du TEST automatisé** : `tests/test_password_validation.py`, `test_6_2_1_password_min_12_chars`, lignes 14–24; commande `.venv/bin/pytest -q tests/test_password_validation.py::test_6_2_1_password_min_12_chars`; sortie attendue `1 passed` (**attendu, non exécuté seul**). Le test couvre 12 accepté et 11 refusé.

**C. Capture de la PREUVE D'EXÉCUTION** : `curl -sS -X POST http://127.0.0.1:5000/api/validate-password -H 'Content-Type: application/json' -d '{"password":"Abcdefghijkl","username":"demo_plain"}'`. Attendu : JSON `valid` selon tous les autres contrôles; refaire avec 11 caractères, attendre une erreur de longueur. **Résultat attendu, non exécuté**; API peut appeler HIBP et exige l'application accessible. Cadrer requête synthétique et JSON, jamais un vrai mot de passe.

**D. Capture des DONNÉES ou CONFIGURATION** : K09 (`PASSWORD_MIN_LENGTH=12`). Aucun secret à afficher.

**E. Documentation** : capturer `docs/AUTHENTICATION_PATHS.md`, lignes 27–36, exigences d'inscription et longueurs.

#### 6.2.2 — Changement de mot de passe possible

**Exigence** : 6.2.2, possibilité de changer le mot de passe.
**Statut** : ⚠️ Partielle : `change_password()` existe, mais aucune route Flask ne l'expose dans l'inventaire.

**A. Capture du CODE**

| N° | Fichier | Fonction ou classe | Lignes | Ce qui doit être visible | Nom conseillé |
|---|---|---|---:|---|---|
| K05 | `backend/auth_register.py` | `change_password` | 549–569 | Recherche utilisateur et contrôles préalable | `6_2_2_code_change.png` |
| K06 | `backend/auth_register.py` | `change_password` | 572–591 | Validation et persistance du nouveau hash | `6_2_2_code_persist.png` |

**B. Capture du TEST automatisé** : `tests/test_password_change.py`, `test_successful_password_change`, lignes 72–97; `.venv/bin/pytest -q tests/test_password_change.py::TestPasswordChangeScenarios::test_successful_password_change`; attendu `1 passed` (**attendu, non exécuté seul**). Le test utilise un faux curseur MySQL, pas un parcours web réel.

**C. Capture de la PREUVE D'EXÉCUTION** : aucune route HTTP de changement trouvée. Capturer la recherche `rg -n "change_password|password-change|change-password" backend/app.py backend/auth_register.py`; montrer la fonction métier et l'absence de route dédiée. Scénario d'API : **non applicable actuellement**. Résultat de cette commande : **résultat attendu, non exécuté dans cette étape**.

**D. Capture des DONNÉES ou CONFIGURATION** : —.

**E. Documentation** : la voie fonctionnelle est décrite dans `docs/AUTHENTICATION_PATHS.md`, lignes 64–69, mais le document ne fournit pas de route web.

#### 6.2.3 — Mot de passe actuel et nouveau exigés

**Exigence** : 6.2.3, changement demandant le mot de passe actuel et le nouveau.
**Statut** : ⚠️ Partielle : le backend exige les deux, mais le changement n'est pas exposé par une route Flask.

**A. Capture du CODE**

| N° | Fichier | Fonction ou classe | Lignes | Ce qui doit être visible | Nom conseillé |
|---|---|---|---:|---|---|
| K05 | `backend/auth_register.py` | `change_password` | 549–569 | Vérification de l'actuel | `6_2_3_code_current.png` |
| K06 | `backend/auth_register.py` | `change_password` | 572–591 | Paramètre du nouveau et mise à jour | `6_2_3_code_new.png` |

**B. Capture du TEST automatisé** : `tests/test_password_change.py`, `test_wrong_current_password`, lignes 99–115; `.venv/bin/pytest -q tests/test_password_change.py::TestPasswordChangeScenarios::test_wrong_current_password`; attendu `1 passed` (**attendu, non exécuté seul**). Il prouve le refus de l'actuel erroné.

**C. Capture de la PREUVE D'EXÉCUTION** : pas de route web. Capture alternative : appel contrôlé depuis console de test à `change_password(user_id, mauvais_actuel, nouveau, ip)` en environnement DB configuré; attendu `success=False`, erreur « Mot de passe actuel incorrect ». **Résultat attendu, non exécuté**; aucun vrai mot de passe dans l'historique ou la capture.

**D. Capture des DONNÉES ou CONFIGURATION** : —.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:64-69` décrit la vérification métier.

#### 6.2.4 — Liste d'au moins 3 000 mots de passe courants compatibles

**Exigence** : 6.2.4, contrôle de 3 000 mots de passe courants respectant la politique.
**Statut** : ❌ Non respectée : fichier = 1 970 entrées uniques, seulement 199 d'au moins 12 caractères, contre 3 000 requis par la cible documentée.

**A. Capture du CODE**

| N° | Fichier | Fonction ou classe | Lignes | Ce qui doit être visible | Nom conseillé |
|---|---|---|---:|---|---|
| K07 | `backend/auth_register.py` | `load_common_passwords` | 38–53 | Chargement de toutes les lignes non vides | `6_2_4_code_load_list.png` |
| K02 | `backend/auth_register.py` | `validate_password` | 244–254 | Comparaison à la liste locale | `6_2_4_code_enforce.png` |

**B. Capture du TEST automatisé** : `tests/test_register.py`, `test_load_common_passwords`, lignes 269–281; `.venv/bin/pytest -q tests/test_register.py::TestUtilityFunctions::test_load_common_passwords`; attendu `1 passed` (**attendu, non exécuté seul**). Le test vérifie quelques éléments connus, pas le seuil 3 000 : il ne prouve pas la conformité.

**C. Capture de la PREUVE D'EXÉCUTION** : afficher les commandes ci-dessous et leur sortie réelle déjà obtenue dans ce dépôt. Elles ne divulguent pas d'identifiant secret :

```bash
wc -l < backend/common_passwords.txt
awk 'NF {n++} END {print n+0}' backend/common_passwords.txt
awk 'NF && length($0) >= 12 {n++} END {print n+0}' backend/common_passwords.txt
sort -fu backend/common_passwords.txt | wc -l
sort -fu backend/common_passwords.txt | awk 'length($0) >= 12 {n++} END {print n+0}'
```

Sorties réelles, dans l'ordre : `2099`, `2099`, `199`, `1970`, `199`. Capturer le terminal entier avec commandes et sorties : le seuil n'est pas atteint.

**D. Capture des DONNÉES ou CONFIGURATION** : `backend/common_passwords.txt` et K10. Ne cadrer que quelques entrées anonymes et la mesure numérique; ne montrer aucune valeur de mot de passe du jeu si la politique du rapport l'interdit.

**E. Documentation** : seuil déclaré de 3 000 dans `backend/config.py:51-52` et description de validation dans `docs/AUTHENTICATION_PATHS.md:27-36`.

#### 6.2.5 — Aucune règle de composition

**Exigence** : 6.2.5, ne pas imposer majuscule/minuscule/chiffre/symbole.
**Statut** : ✅ Respectée dans `validate_password`; les refus contextuels/listes restent appliqués.

**A. Capture du CODE** : K01, `backend/auth_register.py:221-237`, ligne de commentaire explicite qu'aucune composition n'est requise.

**B. Capture du TEST automatisé** : `tests/test_password_validation.py`, `test_6_2_5_no_composition_rules_lowercase_only`, lignes 50–55; commande `.venv/bin/pytest -q tests/test_password_validation.py::test_6_2_5_no_composition_rules_lowercase_only`; attendu `1 passed` (**attendu, non exécuté seul**). Tests supplémentaires `...::test_6_2_5_no_composition_rules_no_symbols` et `...::test_6_2_5_no_composition_rules_no_numbers`.

**C. Capture de la PREUVE D'EXÉCUTION** : POST à `/api/validate-password` avec un mot de passe synthétique de 14 minuscules; attendre aucun message demandant une majuscule/symbole/chiffre. **Résultat attendu, non exécuté**; HIBP peut dépendre du réseau.

**D. Capture des DONNÉES ou CONFIGURATION** : —.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:30-36` décrit les règles de longueur et les listes, sans composition.

#### 6.2.6 — Champs de saisie type=password

**Exigence** : 6.2.6, masquer la saisie des mots de passe.
**Statut** : ❓ Non vérifiable pour inscription/connexion : aucun template frontend présent. Le formulaire de réinitialisation inline utilise `type=password`, mais ce n'est pas une preuve des autres écrans.

**A. Capture du CODE** : capture alternative `backend/app.py:77-105` et du résultat de `rg --files -g '*.html' -g '*.jinja' -g '*.jinja2'`; pas de ligne de template à capturer.

**B. Capture du TEST automatisé** : Aucun test existant. À ajouter : test du DOM rendu des formulaires d'inscription, connexion et changement, assert que tous les champs de mot de passe sont `type=password`.

**C. Capture de la PREUVE D'EXÉCUTION** : ouvrir les formulaires actuels. La route `/register` rend `register.html`, absent du dépôt; capture attendue = erreur template si serveur/DB prêt, mais **résultat attendu, non exécuté**. Capturer aussi la recherche de templates sans résultat.

**D. Capture des DONNÉES ou CONFIGURATION** : —.

**E. Documentation** : —.

#### 6.2.7 — Collage et gestionnaires de mots de passe

**Exigence** : 6.2.7, ne pas bloquer collage ou gestionnaires.
**Statut** : ❓ Non vérifiable : les templates principaux sont absents. Aucun code visible de blocage, mais l'absence de template ne prouve pas l'acceptation du collage.

**A. Capture du CODE** : même preuve alternative que 6.2.6, `backend/app.py:77-105` et recherche des templates; aucune directive `onpaste`/`autocomplete` principale vérifiable.

**B. Capture du TEST automatisé** : Aucun test existant. À ajouter : test navigateur qui colle un mot de passe et vérifie son acceptation dans inscription, login et changement.

**C. Capture de la PREUVE D'EXÉCUTION** : scénario navigateur requis mais non exécutable sans frontend. **Résultat attendu, non exécuté**; ne pas utiliser la page reset inline comme preuve de l'inscription.

**D. Capture des DONNÉES ou CONFIGURATION** : —.

**E. Documentation** : —.

#### 6.2.8 — Vérifier le mot de passe tel que reçu

**Exigence** : 6.2.8, aucun trim, changement de casse ou troncature silencieuse.
**Statut** : ✅ Respectée dans hachage/vérification backend.

**A. Capture du CODE** : K03 (`hash_password`) puis K04 (`verify_password`), fenêtres 15–25 lignes chacune; cadrer l'argument transmis directement à `ph.hash` et `ph.verify`.

**B. Capture du TEST automatisé** : `tests/test_register.py`, `test_password_verification`, lignes 162–174; `.venv/bin/pytest -q tests/test_register.py::TestPasswordHashing::test_password_verification`; attendu `1 passed` (**attendu, non exécuté seul**). Le test démontre correspondance/non-correspondance, pas explicitement espaces/casse.

**C. Capture de la PREUVE D'EXÉCUTION** : console Python de test : hacher une valeur synthétique avec espace final, vérifier cette valeur puis la même sans espace; attendu `True`, puis `False`. **Résultat attendu, non exécuté**; ne jamais afficher le hash complet.

**D. Capture des DONNÉES ou CONFIGURATION** : aucune donnée secrète; masquer hash.

**E. Documentation** : —.

#### 6.2.9 — Accepter au moins 64 caractères

**Exigence** : 6.2.9, mot de passe d'au moins 64 caractères accepté.
**Statut** : ✅ Respectée; maximum applicatif configuré à 128 caractères.

**A. Capture du CODE** : K01 et K09, vérification et limite max.

**B. Capture du TEST automatisé** : `tests/test_password_validation.py`, `test_6_2_1_password_64_chars`, lignes 26–32; `.venv/bin/pytest -q tests/test_password_validation.py::test_6_2_1_password_64_chars`; attendu `1 passed` (**attendu, non exécuté seul**). Pour la borne max, `test_6_2_1_password_128_chars`, lignes 34–40.

**C. Capture de la PREUVE D'EXÉCUTION** : appeler `/api/validate-password` avec une chaîne synthétique de 64 caractères; répéter à 128 puis 129. Attendu politique valide jusqu'à 128 et erreur longueur à 129, sous réserve des autres contrôles. **Résultat attendu, non exécuté**.

**D. Capture des DONNÉES ou CONFIGURATION** : K09 montre `PASSWORD_MAX_LENGTH=128`; ne pas afficher le texte complet du mot de passe de test.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:29-36` indique 12–128.

#### 6.2.10 — Pas de renouvellement périodique obligatoire

**Exigence** : 6.2.10, ne pas forcer une rotation périodique.
**Statut** : ✅ Respectée dans le code relu : aucun champ ou job d'expiration/rotation du mot de passe trouvé. L'expiration de sessions et jetons de récupération ne correspond pas à une rotation de mot de passe.

**A. Capture du CODE** : recherche d'absence, pas de fonction positive à cadrer.

**B. Capture du TEST automatisé** : Aucun test existant. À ajouter : test vérifiant qu'un mot de passe non modifié reste valide au-delà d'une période, sans politique d'expiration utilisateur.

**C. Capture de la PREUVE D'EXÉCUTION** : commande exacte :

```bash
grep -rniE 'password.{0,20}(expire|rotation|renew)|(expire|rotation|renew).{0,20}password' --include='*.py' --include='*.html' --include='*.sql' --exclude-dir=.venv --exclude-dir=.git --exclude-dir=tests .
```

Elle retourne les `expires_at` des jetons V6.4 uniquement, pas d'expiration périodique du mot de passe. **Sortie réelle capturée lors de la préparation :** 4 occurrences toutes dans `backend/password_recovery.py` pour les jetons de reset/MFA. Cadrer commande, périmètre et ces lignes pour éviter de suggérer qu'aucune expiration n'existe.

**D. Capture des DONNÉES ou CONFIGURATION** : `models.User` n'a pas de password expiry; K32 montre séparément la durée de session/reset.

**E. Documentation** : —.

#### 6.2.11 — Liste de mots spécifiques au contexte

**Exigence** : 6.2.11, rejeter des termes du contexte applicatif.
**Statut** : ✅ Respectée dans validation backend.

**A. Capture du CODE** : K02, lignes 237–254, comparaison insensible à la casse; `backend/config.py:20-41` charge la liste.

**B. Capture du TEST automatisé** : `tests/test_asvs_level2.py`, `test_6_2_11_contextual_words_rejected`, lignes 18–33; `.venv/bin/pytest -q tests/test_asvs_level2.py::test_6_2_11_contextual_words_rejected`; attendu `1 passed` (**attendu, non exécuté seul**).

**C. Capture de la PREUVE D'EXÉCUTION** : POST `/api/validate-password` avec `MySecurePassword123`; attendu rejet avec message contextuel générique. **Résultat attendu, non exécuté**.

**D. Capture des DONNÉES ou CONFIGURATION** : capture de `backend/contextual_words.txt` (un mot de test par ligne, pas de secret) et `backend/config.py:20-41`.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:30-36`.

#### 6.2.12 — Contrôle des mots de passe fuités

**Exigence** : 6.2.12, refuser les mots de passe compromis.
**Statut** : ⚠️ Partielle : k-anonymity HIBP existe, mais le défaut `HIBP_FAIL_OPEN=True` accepte quand HIBP est indisponible; les tests observés ont échoué en réseau bloqué.

**A. Capture du CODE** : K08 (`check_password_pwned`) et K10 (`HIBP_FAIL_OPEN`).

**B. Capture du TEST automatisé** : `tests/test_asvs_level2.py`, `test_6_2_12_hibp_on_password_change`, lignes 143–157; `.venv/bin/pytest -q tests/test_asvs_level2.py::test_6_2_12_hibp_on_password_change`; attendu `1 passed` si HIBP répond avec verdict; **dans la suite globale actuellement observée ce test échoue car DNS/réseau indisponible avec fail-open**.

**C. Capture de la PREUVE D'EXÉCUTION** : en réseau contrôlé, tenter un mot de passe de démonstration confirmé par HIBP et montrer son refus. Puis simuler indisponibilité et montrer comportement fail-open configuré. **Non exécuté**; n'utiliser aucune vraie valeur utilisateur.

**D. Capture des DONNÉES ou CONFIGURATION** : K10 et logs HIBP; masquer le mot de passe et les valeurs SHA-1 complètes, garder seulement que le préfixe est envoyé.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:33-36`.

### V6.3 — Sécurité générale

#### 6.3.1 — Bourrage d'identifiants et force brute

**Exigence** : 6.3.1, limitation par IP, identifiant/IP et identifiant avec délai.
**Statut** : ⚠️ Partielle : implémentation multi-niveaux visible; les tests intégrés demandent MySQL inaccessible dans la vérification actuelle.

**A. Capture du CODE** : K11, K12a, K12b, K12c, K13. Chaque fenêtre est ≤25 lignes; assembler en planche avec légende a/b/c.

**B. Capture du TEST automatisé** :

| Fichier | Test exact | Lignes | Ce que ça prouve | Commande seule | Sortie attendue |
|---|---|---:|---|---|---|
| `tests/test_asvs_v6_3.py` | `test_6_3_1_no_account_lockout_dos_from_different_ip` | 99–123 | IP attaquant différente ne bloque pas victime | `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_1_no_account_lockout_dos_from_different_ip` | `1 passed` attendu, dépend MySQL |
| même | `test_6_3_1_progressive_delay_on_failures` | 125–145 | délai/backoff | `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_1_progressive_delay_on_failures` | `1 passed` attendu, dépend MySQL |
| même | `test_6_3_1_only_failures_counted_for_lockout` | 147–165 | seuls échecs comptés | `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_1_only_failures_counted_for_lockout` | `1 passed` attendu, dépend MySQL |
| même | `test_6_3_1_uniform_lockout_message` | 167–185 | message blocage uniforme | `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_1_uniform_lockout_message` | `1 passed` attendu, dépend MySQL |

Tous ci-dessus : attendu, aucun lancé seul. La suite complète a 30 erreurs DB, qui empêchent de conclure aux assertions d'intégration.

**C. Capture de la PREUVE D'EXÉCUTION** : avec DB de test et compte synthétique, envoyer 6 POST login échoués au même couple IP/identifiant puis un 7e; attendre délai/blocage (limites exactes dans config). Faire une seconde série de 21 identifiants depuis la même IP; attendre blocage IP. **Résultat attendu, non exécuté**. Les templates de login manquent, donc vérifier aussi si POST finit en erreur de rendu après l'authentification.

**D. Capture des DONNÉES ou CONFIGURATION** : K11 et table `LoginAttempt` ORM, `backend/models.py:75-92`. Pour les événements, afficher uniquement compte de lignes/horodatages/IP de documentation (IP synthétique).

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:41-53` (seuils annoncés; distinguer paramètres configurés et preuve live).

#### 6.3.2 — Aucun compte par défaut

**Exigence** : 6.3.2, absence de comptes ou identifiants préconfigurés.
**Statut** : ✅ Respectée par le code relu : création admin explicite via CLI; aucun utilisateur précréé trouvé. Le défaut `role='user'` est une valeur de champ, pas un compte.

**A. Capture du CODE** : K15, mot de passe fourni, validation, contrôle d'unicité, création explicite.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py`, `test_6_3_2_no_default_accounts`, lignes 187–195; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_2_no_default_accounts`; attendu `1 passed` mais requiert MySQL. Aussi `test_6_3_2_create_admin_cli_requires_strong_password`, lignes 197–223.

**C. Capture de la PREUVE D'EXÉCUTION** :

```bash
grep -rniE 'default.{0,20}(user|account|password)|(user|account).{0,20}default' --include='*.py' --include='*.sql' --exclude-dir=.venv --exclude-dir=.git --exclude-dir=tests .
```

La recherche retourne des défauts de rôle/champs ORM, pas une création de compte; compléter par `python backend/create_admin.py --help`. **Sortie `--help` attendue, non exécutée ici**. Ne pas afficher le mot de passe admin.

**D. Capture des DONNÉES ou CONFIGURATION** : aucun compte démo réel. Pour la base de test, utiliser une requête ORM filtrant `User.role == 'admin'`, afficher seulement le compte synthétique.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:77-80`.

#### 6.3.3 — Authentification multifacteur

**Exigence** : 6.3.3, le second facteur est vérifié avant la session quand le MFA est actif.
**Statut** : ⚠️ Partielle : MFA n'est pas imposé à tous les comptes (`mfa_enabled` false par défaut); `app.login` transmet TOTP mais pas le code de récupération.

**A. Capture du CODE** : K14b (MFA requis et validation), K16 (TOTP/anti-rejeu), `backend/models.py:108-134` pour stockage (cadrer structure uniquement, masquer secret). Pour l'absence d'obligation universelle, `backend/models.py:27-45` et `backend/create_admin.py:71-78`.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py`, `test_6_3_3_cannot_login_without_mfa`, lignes 225–245 et 246–252; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_3_cannot_login_without_mfa`; attendu `1 passed`, DB requise. Autres : `test_6_3_3_totp_replay_rejected` lignes 254–274; `test_6_3_3_recovery_code_single_use` lignes 276–300.

**C. Capture de la PREUVE D'EXÉCUTION** : compte démo avec MFA actif, POST `/login` sans `totp_code` → le code métier retourne MFA requis et aucun jeton; POST avec TOTP valide → session. **Résultat attendu, non exécuté** (DB et modèle d'écran manquants). Capturer un token masqué. Noter que l'UI actuelle ne passe pas `recovery_code` à `authenticate_user`.

**D. Capture des DONNÉES ou CONFIGURATION** : `backend/config.py:82-94` (période, taille secret, quantité de codes); `backend/models.py:108-134` structure MFA. Ne pas montrer secret TOTP, QR, code secours ou hash.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:54-62`.

#### 6.3.4 — Cohérence des voies d'authentification

**Exigence** : 6.3.4, voies et protections cohérentes.
**Statut** : ⚠️ Partielle : le login et reset appliquent des contrôles; pas de route web au changement de mot de passe, et l'UI login ne transmet pas code secours.

**A. Capture du CODE** : K13–K14b; routes courantes `backend/app.py:77-160`, routes reset `backend/app.py:251-300` (pour tenir 25 lignes, prendre 2 captures: 251–264 et 264–283, plus 286–300). Une capture par route doit montrer appel métier/rate-limit/MFA applicable.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py`, `test_6_3_4_no_bypass_and_password_change_rate_limited`, lignes 307–330; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_4_no_bypass_and_password_change_rate_limited`; attendu `1 passed`, nécessite MySQL. `tests/test_asvs_level2.py`, `test_6_3_4_authentication_paths_documented`, lignes 159–166; commande `.venv/bin/pytest -q tests/test_asvs_level2.py::test_6_3_4_authentication_paths_documented`, attendu `1 passed` (ne vérifie que l'existence de la doc).

**C. Capture de la PREUVE D'EXÉCUTION** : utiliser inventaire route par route et tester login sans MFA code, reset sans MFA code sur un compte MFA, changement de mot de passe via méthode métier, et reset rate limit. **Non exécuté**; pas de route de changement UI. Cadrer réponses et résultat HTTP sans cookie/token.

**D. Capture des DONNÉES ou CONFIGURATION** : K11, K32; table de synthèse de route dans `docs/AUTHENTICATION_PATHS.md`.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:8-21, 25-75`.

#### 6.3.5 — Notifications de tentatives suspectes

**Exigence** : 6.3.5, notifier les cas suspects configurés.
**Statut** : ⚠️ Partielle : appels et événements existent; par défaut les notifications sont seulement journalisées en développement.

**A. Capture du CODE** : K18a/K18b et K19a/K19b/K19c pour les quatre déclencheurs. Chaque fenêtre est ≤25 lignes; triggers : nouvel appareil/IP, échecs répétés, MFA échoué, retour après inactivité.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py`, `test_6_3_5_suspicious_notifications`, lignes 332–353 (appareil), 350–371 (échec MFA/succès après échecs), 373–394 (inactivité et absence de secrets), trois cadrages courts; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_5_suspicious_notifications`; attendu `1 passed`, DB et service mock requis.

**C. Capture de la PREUVE D'EXÉCUTION** : avec service SMTP de test configuré, déclencher une nouvelle IP, plusieurs échecs puis succès, échec MFA, reconnexion après 30 jours; capturer quatre messages dans boîte de test ou logs SMTP sans données personnelles. **Résultat attendu, non exécuté**.

**D. Capture des DONNÉES ou CONFIGURATION** : K35 montre dev logger; K36 montre SMTP. Le backend par défaut est `dev` (`backend/notifications.py:255-264`); sans SMTP, aucune livraison réelle n'est prouvée.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:84-106`.

#### 6.3.6 — Email non utilisé comme authentificateur

**Exigence** : 6.3.6, aucun facteur email pour l'authentification primaire/MFA.
**Statut** : ✅ Respectée dans les routes de login/MFA relues. L'email est utilisé pour récupération/notification, pas comme facteur de connexion.

**A. Capture du CODE** : K14b et K17; compléter avec recherche source ci-dessous, car l'absence est la preuve.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py`, `test_6_3_6_no_email_authentication_factor`, lignes 400–414; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_6_no_email_authentication_factor`; attendu `1 passed` (**attendu, non exécuté seul**, DB fixture).

**C. Capture de la PREUVE D'EXÉCUTION** :

```bash
grep -rniE 'email.{0,20}(factor|otp|totp|authenticate)|(factor|otp|totp|authenticate).{0,20}email' --include='*.py' --include='*.html' --include='*.sql' --exclude-dir=.venv --exclude-dir=.git --exclude-dir=tests .
```

Sortie réelle lors de la préparation : `Aucun résultat` pour le code produit. Capturer commande, exclusions, résultat. Les liens de reset ne doivent pas être décrits comme facteur de login.

**D. Capture des DONNÉES ou CONFIGURATION** : —.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:54-62` et 125–134 (email utilisé récupération, pas login).

#### 6.3.7 — Notification après modification des identifiants

**Exigence** : 6.3.7, notification après mise à jour des credentials.
**Statut** : ⚠️ Partielle : appels pour changement password/email/username présents; backend par défaut dev journalise sans mail réel.

**A. Capture du CODE** : K20a/K20b et K21/K37/K38. Capturer les fenêtres exactes de l'inventaire K; chacune montre l'appel service après commit.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py`, `test_6_3_7_credential_update_notifications`, lignes 416–435 (password), 436–455 (email/username); `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_7_credential_update_notifications`; attendu `1 passed`, DB fixture et notifications mock.

**C. Capture de la PREUVE D'EXÉCUTION** : changer le mot de passe et l'email d'un compte de test via fonctions métier; capturer message correspondant dans SMTP sandbox et le compte destinataire (masqué). **Non exécuté**; dans le mode dev, capturer le log en l'identifiant explicitement comme journalisation locale et jamais comme livraison.

**D. Capture des DONNÉES ou CONFIGURATION** : K35/K36 et configuration SMTP (n'afficher aucune valeur SMTP secrète).

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:64-75` et 110-123.

#### 6.3.8 — Ne pas déduire les utilisateurs valides

**Exigence** : 6.3.8, réponses génériques et temps comparables.
**Statut** : ⚠️ Partielle : hash factice et message login générique visibles; les routes HTML dépendent de templates absents, et le reset envoie le mail de manière synchrone, donc son temps peut différer.

**A. Capture du CODE** : K14a et K22; pour l'inscription, capturer `backend/auth_register.py:396-402` (validation du mot de passe) puis `backend/auth_register.py:404-416` (contrôle de disponibilité et message générique). Reset K25 montre le hash dummy.

**B. Capture du TEST automatisé** : `tests/test_asvs_v6_3.py` : `test_6_3_8_anti_enumeration_login`, lignes 460–477; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_8_anti_enumeration_login`; `test_6_3_8_timing_attack_response_comparable`, 479–500; `.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_8_timing_attack_response_comparable`; `test_6_3_8_registration_response_generic`, 503–521; commande correspondante. Attendu 1 passed chacun, tests DB et HIBP potentiellement réseau.

**C. Capture de la PREUVE D'EXÉCUTION** : pour au moins 10 essais de chaque cas, utiliser un client HTTP de test configuré avec DB. Exemple timing (commande exacte, prévoir un cookie jar temporaire et ne conserver aucun secret) :

```bash
for kind in exist absent; do
  for n in $(seq 1 10); do
    user=demo_absent; [ "$kind" = exist ] && user=demo_plain
    curl -sS -o /dev/null -w "$kind %{http_code} %{time_total}\n" \
      -X POST http://127.0.0.1:5000/login \
      --data-urlencode "username=$user" --data-urlencode 'password=WrongSyntheticPassword!'
  done
done
```

Ce scénario **n'a pas été exécuté**; attendu : codes/messages même type et distribution de temps comparée, pas une valeur fixe. Mais le template login est absent et la DB locale est indisponible, donc des réponses 500 sont possibles avant configuration. Compléter par deux réponses login côte à côte et doublon inscription; cadrer structure/message/HTTP sans mot de passe. Ne pas conclure sur un écart statistique avec seulement une paire.

**D. Capture des DONNÉES ou CONFIGURATION** : K22 et `backend/config.py:122-127` hash factice/messages; K25 pour reset générique. Ne pas montrer le hash factice complet comme un secret réel (il est constant de test, on peut le masquer).

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:37-53` et `docs/AUTHENTICATION_PATHS.md:125-134`.

### V6.4 — Récupération et cycle de vie

#### 6.4.1 — Secrets initiaux aléatoires/expirants

**Exigence** : 6.4.1, mots de passe initiaux/codes d'activation système générés aléatoirement, courts et à usage unique.
**Statut** : ✅ Respectée pour les jetons de récupération présents; l'application ne génère pas de mot de passe initial.

**A. Capture du CODE** : K23, K24, K32. Le token est `secrets.token_urlsafe(32)`, hashé SHA-256 et expiré à 20 minutes.

**B. Capture du TEST automatisé** : `tests/test_password_recovery.py`, `test_reset_request_is_neutral_and_stores_only_hash`, lignes 49–60; `.venv/bin/pytest -q tests/test_password_recovery.py::test_reset_request_is_neutral_and_stores_only_hash`; attendu `1 passed` (**résultat déjà observé dans la suite ciblée antérieure**, non relancé individuellement maintenant). Couvre hash/TTL.

**C. Capture de la PREUVE D'EXÉCUTION** : avec SMTP sandbox, demander reset et utiliser un seul token synthétique; après première utilisation, deuxième tentative renvoie HTTP 400. **Non exécuté en HTTP**; les quatre tests service ont précédemment passé.

**D. Capture des DONNÉES ou CONFIGURATION** : K23/K32; inspection ORM `PasswordResetToken` n'afficher que `purpose`, timestamps et booléen `used_at != None`, jamais `token_hash` complet ni URL.

**E. Documentation** : `docs/ASVS_V6_4_VERIFICATION.md:28-35` et `docs/AUTHENTICATION_PATHS.md:125-134`.

#### 6.4.2 — Pas d'indice ni de question secrète

**Exigence** : 6.4.2, aucun authentificateur fondé sur une connaissance de type question/indice.
**Statut** : ✅ Respectée dans le périmètre du code/fichiers recherché; base déployée non inspectée.

**Description humanisée pour le rapport** : Nous avons vérifié dans les sources du projet qu'aucun indice de mot de passe ni aucune question secrète n'est proposé comme moyen d'authentification ou de récupération. La recherche des termes liés aux indices et questions secrètes n'a renvoyé aucun résultat dans les fichiers Python, HTML et SQL examinés. Cette preuve est une vérification du code, et non un test unitaire dédié; elle ne couvre pas une base de données déployée qui n'a pas été inspectée.

**A. Capture du CODE** : preuve d'absence par recherche, pas de fonction à capturer.

**B. Capture du TEST automatisé** : Aucun test valide spécifique existant. `test_6_4_2_no_password_reset` est mal nommé/obsolète et ne prouve pas cette exigence. À ajouter : test de schéma ORM + recherche AST des champs/handlers hint/security-question.

**C. Capture de la PREUVE D'EXÉCUTION** : commande exacte (déjà exécutée; aucun résultat) :

```bash
grep -rniE 'password.?hint|hint.?password|security.?question|secret.?question|memorable' \
  --include='*.py' --include='*.html' --include='*.sql' \
  --exclude-dir=.venv --exclude-dir=.git .
```

Sortie réelle : aucun résultat. Cadrer termes, scope et ligne « aucun résultat ». La base de production reste hors périmètre de cette recherche.

**D. Capture des DONNÉES ou CONFIGURATION** : aucun champ de connaissance trouvé dans `backend/models.py`; impossible de démontrer un schéma déployé sans DB.

**E. Documentation** : —.

#### 6.4.3 — Reset sécurisé et MFA non contourné

**Exigence** : 6.4.3, reset oublié sûr sans contourner MFA.
**Statut** : ⚠️ Partielle tant qu'un mail réel n'est pas livré et que la différence temporelle requête connue/inconnue n'est pas corrigée/mesurée.

**Description humanisée pour le rapport** : Nous avons mis en place une réinitialisation par jeton aléatoire dont seul le hash est conservé, avec expiration et usage unique. Le nouveau mot de passe est vérifié par `validate_password()`; si le MFA est actif, le parcours exige aussi un TOTP ou un code de récupération, puis invalide les sessions. Le module de tests ciblé a été exécuté : **4 tests passés**, dont ceux qui vérifient une réponse neutre et le hash du jeton, l'usage unique et l'invalidation des sessions, ainsi que le refus de contourner le MFA. Ces tests utilisent une notification simulée : nous ne déclarons donc pas la livraison du courriel conforme tant qu'un envoi réel n'a pas été vérifié; la comparabilité du temps de réponse reste également à mesurer.

**A. Capture du CODE** : K23–K26b, K29. Chaque capture ≤25 lignes; cadrer hash stockage, TTL/usage unique, neutralité, MFA, sessions invalidées, notification.

**B. Capture du TEST automatisé** : `tests/test_password_recovery.py` : `test_reset_request_is_neutral_and_stores_only_hash` 49–60; `test_reset_is_one_use_and_invalidates_sessions` 63–73; `test_reset_does_not_bypass_enabled_mfa` 88–98. Commandes `.venv/bin/pytest -q tests/test_password_recovery.py::test_reset_request_is_neutral_and_stores_only_hash` etc. Attendu 1 passed chacun; le module entier a **4 passed** dans le test ciblé antérieur; pas de test route Flask ou vrai email.

**C. Capture de la PREUVE D'EXÉCUTION** :

```bash
curl -i -X POST http://127.0.0.1:5000/password-reset -H 'Content-Type: application/json' -d '{"identifier":"demo_plain"}'
curl -i -X POST http://127.0.0.1:5000/password-reset/confirm -H 'Content-Type: application/json' -d '{"token":"TOKEN_DE_TEST","new_password":"SyntheticNewPassword2026!"}'
```

Avec MFA actif, répéter sans code puis avec TOTP (ou code secours par API JSON). Attendu : demande toujours HTTP 200/message générique; finalisation MFA sans facteur HTTP 400; token utilisé/expiré HTTP 400; succès HTTP 200. **Résultat attendu, non exécuté**; remplacer token par valeur reçue dans SMTP sandbox, jamais dans capture.

**D. Capture des DONNÉES ou CONFIGURATION** : K32 TTL; K35/K36 envoi; table reset ORM uniquement dates/usage/motif, masquer hash et tout token.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:16-19,125-134`.

#### 6.4.4 — Perte MFA, preuve au niveau inscription

**Exigence** : 6.4.4, preuve de récupération au moins au niveau d'inscription.
**Statut** : ⚠️ Partielle : récupération exige session MFA existante (TOTP ou code secours), mot de passe actuel et lien email; dépend du mail et ne couvre pas la perte de tous les facteurs/secrets de boîte.

**Description humanisée pour le rapport** : Pour remplacer un facteur MFA perdu, le code ne se contente pas du mot de passe : il exige une session déjà authentifiée, un lien à usage unique envoyé à l'adresse enregistrée et la confirmation du mot de passe actuel. Après validation, les anciens secrets et codes de secours sont supprimés, les sessions sont invalidées et un nouvel enrôlement MFA est imposé. Le code matérialise ces contrôles, mais aucun test unitaire dédié au parcours complet de récupération/réenrôlement n'existe actuellement; la livraison du courriel doit aussi être démontrée avant de conclure à une conformité complète.

**A. Capture du CODE** : K17, K27, K30–K31, K34. Cadrer suppression anciens secret/codes, invalidation sessions et obligation de réenrôlement.

**B. Capture du TEST automatisé** : Aucun test dédié de récupération MFA/réenrôlement existant. À ajouter : test d'un utilisateur connecté via code secours + lien email + mot de passe, suppression anciens facteurs/sessions, refus login complet avant nouvel enrôlement. Ne pas prendre le test de réinitialisation password comme preuve de 6.4.4.

**C. Capture de la PREUVE D'EXÉCUTION** : compte de démonstration MFA; se connecter avec code secours, demander `/mfa/recovery/request`, ouvrir email sandbox dans même session, confirmer mot de passe actuel; vérifier cookie/session révoqué, se reconnecter et voir écran d'enrôlement obligatoire. **Résultat attendu, non exécuté**. Le lien doit être accessible sur le même navigateur/session car la confirmation est `login_required`.

**D. Capture des DONNÉES ou CONFIGURATION** : modèles `MfaSecret`, `MfaRecoveryCode`, `MfaReenrollment` et logs de notification; masquer tous secrets/codes/tokens.

**E. Documentation** : `docs/ASVS_V6_4_VERIFICATION.md:30-35,39-48`; `docs/AUTHENTICATION_PATHS.md:130-132` documentent niveau d'assurance supposé.

#### 6.4.5 — Rappels avant expiration authentificateur

**Exigence** : 6.4.5, rappels envoyés avant expiration des authentificateurs qui expirent.
**Statut** : ➖ Non applicable selon les objets trouvés : sessions et jetons expirent; aucun mot de passe/certificat/token matériel utilisateur n'a d'expiration périodique avec renouvellement planifié.

**Description humanisée pour le rapport** : Nous n'avons pas de mécanisme d'authentification utilisateur à renouvellement périodique dans le périmètre du projet; il n'y a donc pas d'échéance d'authentificateur qui nécessite des rappels automatiques. La recherche actuelle ne relève que des expirations de sessions et de jetons de récupération, qui sont des mécanismes temporaires et non des authentificateurs à renouveler. L'exigence est donc notée non applicable, et non déclarée respectée grâce à un test de rappel.

**A. Capture du CODE** : commande d'absence ci-dessous; K32 peut illustrer les expirations de session/reset qui ne nécessitent pas de rappel d'authenticator.

**B. Capture du TEST automatisé** : Aucun test existant. À ajouter uniquement si une politique d'expiration authentificateur est introduite; vérifier rappels planifiés avant échéance et répétition automatique.

**C. Capture de la PREUVE D'EXÉCUTION** : recherche exacte dans Python/config/templates :

```bash
grep -rniE 'password.{0,20}(expire|rotation|renew)|(expire|rotation|renew).{0,20}password' --include='*.py' --include='*.html' --include='*.sql' --exclude-dir=.venv --exclude-dir=.git --exclude-dir=tests .
```

Sortie réelle : occurrences `expires_at` limitées aux jetons password/MFA de `backend/password_recovery.py`; aucun rappel périodique. Une recherche séparée de tâches planifiées peut être capturée avec `rg -n 'cron|schedule|scheduler|reminder|renewal' --glob '*.py' .` (**résultat attendu, non exécuté**).

**D. Capture des DONNÉES ou CONFIGURATION** : K32 montre TTL reset, `backend/config.py:110` durée de session; pas de date d'expiration password dans User.

**E. Documentation** : ajouter/montrer l'état « non applicable » dans rapport final; aucun guide de renouvellement existant.

#### 6.4.6 — Reset initié par admin, sans choisir le mot de passe

**Exigence** : 6.4.6, admin initie; seul utilisateur reçoit le jeton et choisit le mot de passe.
**Statut** : ⚠️ Partielle tant que le service email ne livre pas réellement le lien.

**Description humanisée pour le rapport** : Un administrateur peut déclencher une réinitialisation, mais le contrôle du rôle est fait côté serveur par `admin_required`. Le code génère le jeton et transmet les instructions à l'adresse enregistrée de l'utilisateur; la réponse renvoyée à l'administrateur ne contient ni jeton ni mot de passe. Le test unitaire `test_reset_admin_metadata_does_not_return_secret` contrôle que le résultat du service ne divulgue pas le jeton et que l'initiateur est enregistré. Il ne teste toutefois pas l'autorisation HTTP de la route, et le backend de développement journalise le message au lieu de l'envoyer : la conformité complète reste à confirmer avec un test de route et un SMTP de test.

**A. Capture du CODE** : K28–K30, K23 et `backend/app.py:286-293`. Montrer guard role serveur, chemin cible ID, absence de secret dans réponse; capturer le modèle avec `initiated_by_user_id` et `created_at`.

**B. Capture du TEST automatisé** : `tests/test_password_recovery.py`, `test_reset_admin_metadata_does_not_return_secret`, lignes 76–85; `.venv/bin/pytest -q tests/test_password_recovery.py::test_reset_admin_metadata_does_not_return_secret`; attendu `1 passed` (**déjà dans module ciblé**, pas lancé isolément). Il teste métadonnées/service mais pas le guard admin HTTP. À ajouter : test client rôle user→403, admin→200, réponse sans token/password.

**C. Capture de la PREUVE D'EXÉCUTION** : après créer deux comptes de démo : `curl -i -b admin.cookies -X POST http://127.0.0.1:5000/admin/users/ID/password-reset`; attendre HTTP 200 neutre sans champ secret, et email reset chez utilisateur. Répéter avec cookie utilisateur, attendre 403. **Résultat attendu, non exécuté**. Ne jamais utiliser `--data password=...`.

**D. Capture des DONNÉES ou CONFIGURATION** : ligne ORM du jeton affiche uniquement user_id de test, initiator `admin`, created_at, purpose; masquer token_hash. Capturer email reçu avec destinataire masqué et lien entièrement masqué.

**E. Documentation** : `docs/AUTHENTICATION_PATHS.md:18,125-134`; rapport V6.4.

## 5. Ordre conseillé et bloc de commandes

### Ordre conseillé pour les captures

1. Préparer MySQL jetable, configurer SMTP sandbox et comptes synthétiques; vérifier qu'aucun secret réel n'est affiché.
2. Démarrer MySQL puis l'application. Vérifier d'abord route reset (elle n'utilise pas les templates généraux) et statut de l'email sandbox.
3. Capturer le code K01–K36 et config/test immédiatement avant les manipulations, avec numéros visibles.
4. Parcours mot de passe : validation 12/11/64/128/129, changement backend, HIBP accessible, message contextuel, collage/UI dès qu'un vrai frontend existe.
5. Parcours connexion : brute force IP et couple; compte MFA sans TOTP puis avec TOTP; notifications nouvelles IP/échecs/inactivité; comparer existant/inexistant sur au moins 10 essais chacun.
6. Parcours V6.4 : demande reset existant et absent; finaliser MFA et non-MFA; retenter token; vérifier session annulée; admin puis compte non-admin; récupération MFA et réenrôlement.
7. Capturer email SMTP de test/logs et résultats de tests; terminer par commandes de recherche d'absence et captures de documentation.

### Bloc unique — lancement des tests individuels dans l'ordre

Chaque commande ci-dessous est une commande de test seule. **Résultat attendu, non exécuté seul** signifie qu'aucune exécution individuelle n'est revendiquée; les tests DB peuvent échouer au setup MySQL, et les tests HIBP nécessitent accès réseau.

```bash
# V6.2
.venv/bin/pytest -q tests/test_password_validation.py::test_6_2_1_password_min_12_chars
.venv/bin/pytest -q tests/test_password_change.py::TestPasswordChangeScenarios::test_successful_password_change
.venv/bin/pytest -q tests/test_password_change.py::TestPasswordChangeScenarios::test_wrong_current_password
.venv/bin/pytest -q tests/test_register.py::TestPasswordValidation::test_common_passwords_validation
.venv/bin/pytest -q tests/test_password_validation.py::test_6_2_5_no_composition_rules_lowercase_only
# 6.2.6 : aucun test existant
# 6.2.7 : aucun test existant
.venv/bin/pytest -q tests/test_register.py::TestPasswordHashing::test_password_verification
.venv/bin/pytest -q tests/test_password_validation.py::test_6_2_1_password_64_chars
# 6.2.10 : aucun test existant
.venv/bin/pytest -q tests/test_asvs_level2.py::test_6_2_11_contextual_words_rejected
.venv/bin/pytest -q tests/test_asvs_level2.py::test_6_2_12_hibp_on_password_change
# V6.3
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_1_uniform_lockout_message
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_2_no_default_accounts
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_3_cannot_login_without_mfa
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_4_no_bypass_and_password_change_rate_limited
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_5_suspicious_notifications
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_6_no_email_authentication_factor
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_7_credential_update_notifications
.venv/bin/pytest -q tests/test_asvs_v6_3.py::test_6_3_8_anti_enumeration_login
.venv/bin/pytest -q tests/test_password_recovery.py::test_reset_request_is_neutral_and_stores_only_hash
# V6.4.2 : aucun test sémantiquement pertinent (test historique mal nommé)
# V6.4.3 : couvert partiellement par tests/test_password_recovery.py
# V6.4.4 : aucun test existant
# V6.4.5 : aucun test existant (N/A)
.venv/bin/pytest -q tests/test_password_recovery.py::test_reset_admin_metadata_does_not_return_secret
```

Sortie réelle de lancement global, exécuté pendant la préparation du guide : `.venv/bin/pytest -q` → **51 passed, 3 failed, 30 errors**. Les 30 erreurs sont des échecs de connexion à MySQL local; 3 échecs sont les assertions HIBP avec réseau absent/fail-open. La commande ciblée `.venv/bin/pytest -q tests/test_password_recovery.py` exécutée pendant la préparation a rendu **4 passed**. Les commandes individuelles ci-dessus ne sont pas déclarées exécutées.

## 6. Récapitulatif de toutes les captures proposées

Une ligne représente un asset de capture. Plusieurs exigences peuvent pointer vers le même asset K si le cadrage est identique; la liste des K est au §3.

| N° | Exigence | Type | Fichier ou écran | Lignes ou commande | Nom conseillé |
|---|---|---|---|---|---|
| 01 | 6.2.1 | code | `backend/auth_register.py` | 221–237 (K01) | `6_2_1_code_validation.png` |
| 02 | 6.2.1 | données | `backend/config.py` | 14–18 (K09) | `6_2_1_config_minimum.png` |
| 03 | 6.2.1 | test | test password validation | 14–24 | `6_2_1_test_minimum.png` |
| 04 | 6.2.1 | exécution | curl password validation | commande fiche | `6_2_1_execution_minimum.png` |
| 05 | 6.2.2 | code | `backend/auth_register.py` | 549–569, 572–591 | `6_2_2_code_change.png` |
| 06 | 6.2.2 | test | test password change | 72–97 | `6_2_2_test_change.png` |
| 07 | 6.2.2 | exécution | recherche route | `rg -n "change_password|password-change|change-password" backend/app.py backend/auth_register.py` | `6_2_2_absence_route.png` |
| 08 | 6.2.3 | code | `backend/auth_register.py` | 549–569, 572–591 | `6_2_3_code_current_new.png` |
| 09 | 6.2.3 | test | wrong current | 99–115 | `6_2_3_test_wrong_current.png` |
| 10 | 6.2.3 | exécution | console métier | appel fiche, mauvais actuel | `6_2_3_execution_wrong_current.png` |
| 11 | 6.2.4 | code | `backend/auth_register.py` | 38–53, 244–254 | `6_2_4_code_list_check.png` |
| 12 | 6.2.4 | données | liste locale | wc/awk/sort commands fiche | `6_2_4_count_list.png` |
| 13 | 6.2.4 | test | `test_load_common_passwords` | 269–281 | `6_2_4_test_list.png` |
| 14 | 6.2.4 | exécution | terminal | compte unique/longueur minimale | `6_2_4_execution_shortfall.png` |
| 15 | 6.2.5 | code | `backend/auth_register.py` | 221–237 (K01) | `6_2_5_code_no_composition.png` |
| 16 | 6.2.5 | test | no composition | 50–55 | `6_2_5_test_lowercase.png` |
| 17 | 6.2.5 | exécution | `/api/validate-password` | POST fiche | `6_2_5_execution_lowercase.png` |
| 18 | 6.2.6 | code | `backend/app.py` + recherche templates | 77–105; `rg --files -g '*.html' -g '*.jinja*'` | `6_2_6_absence_frontend.png` |
| 19 | 6.2.6 | exécution | terminal | même `rg --files` sans résultat | `6_2_6_search_templates.png` |
| 20 | 6.2.7 | code | `backend/app.py` + recherche templates | 77–105 | `6_2_7_absence_frontend.png` |
| 21 | 6.2.7 | exécution | navigateur/terminal | collage non vérifiable sans frontend | `6_2_7_non_verifiable.png` |
| 22 | 6.2.8 | code | `backend/auth_register.py` | 256–276, 278–298 | `6_2_8_code_hash_verify.png` |
| 23 | 6.2.8 | test | `test_password_verification` | 162–174 | `6_2_8_test_verification.png` |
| 24 | 6.2.8 | exécution | console Python | valeur avec/sans espace, hash masqué | `6_2_8_execution_as_received.png` |
| 25 | 6.2.9 | code | `backend/config.py`/validation | 14–18, 221–228 | `6_2_9_code_maximum.png` |
| 26 | 6.2.9 | test | test longueur 64/128 | 26–40 | `6_2_9_test_lengths.png` |
| 27 | 6.2.9 | exécution | API validation | longueurs 64,128,129 | `6_2_9_execution_lengths.png` |
| 28 | 6.2.10 | code | recherche d'absence | grep expiry/rotation commande fiche | `6_2_10_no_rotation_code.png` |
| 29 | 6.2.10 | exécution | terminal | occurrences reset token seulement | `6_2_10_search_expiry.png` |
| 30 | 6.2.11 | code | `backend/auth_register.py`, config | 237–254; `backend/config.py:20-41` | `6_2_11_code_context_words.png` |
| 31 | 6.2.11 | test | contextual rejected | 18–33 | `6_2_11_test_context.png` |
| 32 | 6.2.11 | exécution | API validation | mot `MySecurePassword123` | `6_2_11_execution_rejected.png` |
| 33 | 6.2.11 | données | `backend/contextual_words.txt` | mots de test anonymes | `6_2_11_context_list.png` |
| 34 | 6.2.12 | code | HIBP/config | 83–103; config 43–52 | `6_2_12_code_hibp.png` |
| 35 | 6.2.12 | test | HIBP change | 143–157 | `6_2_12_test_hibp.png` |
| 36 | 6.2.12 | exécution | terminal + log HIBP | test leaked pass, masque valeur | `6_2_12_execution_hibp.png` |
| 37 | 6.2.12 | données | config/log | fail-open et statut réseau | `6_2_12_config_fail_open.png` |
| 38 | 6.3.1 | code | rate config & ORM | K11–K12c | `6_3_1_code_thresholds.png` |
| 39 | 6.3.1 | tests | quatre tests rate | lignes 99–185 du fichier test | `6_3_1_tests_rate.png` |
| 40 | 6.3.1 | exécution | rafales login | 6 identifiant/IP, 21 IP | `6_3_1_execution_burst.png` |
| 41 | 6.3.1 | données/config | `backend/config.py`, ORM attempts | 58–76; `backend/models.py:75-92` | `6_3_1_data_config.png` |
| 42 | 6.3.1 | documentation | auth paths | 41–53 | `6_3_1_doc_paths.png` |
| 43 | 6.3.2 | code | `backend/create_admin.py` | 49–68 | `6_3_2_code_admin_create.png` |
| 44 | 6.3.2 | test | no default admin | 187–223 | `6_3_2_tests_default.png` |
| 45 | 6.3.2 | exécution | grep + CLI help | commande fiche | `6_3_2_execution_search.png` |
| 46 | 6.3.2 | documentation | auth paths | 77–80 | `6_3_2_doc_admin.png` |
| 47 | 6.3.3 | code | login/MFA | 467–509, `backend/auth_mfa.py:110-132` | `6_3_3_code_mfa_before_session.png` |
| 48 | 6.3.3 | test | MFA no session/replay | 225–305 | `6_3_3_tests_mfa.png` |
| 49 | 6.3.3 | exécution | login with/without TOTP | HTTP scenario fiche | `6_3_3_execution_mfa.png` |
| 50 | 6.3.3 | données/config | MFA models/config | models 108–134; config 82–94 | `6_3_3_data_mfa.png` |
| 51 | 6.3.3 | documentation | auth paths | 54–62 | `6_3_3_doc_mfa.png` |
| 52 | 6.3.4 | code | routes and auth methods | `backend/app.py:77-160,251-300` split | `6_3_4_code_paths.png` |
| 53 | 6.3.4 | tests | no bypass + docs | test lines 307–330; level2 test | `6_3_4_tests_paths.png` |
| 54 | 6.3.4 | exécution | matrix routes | login/reset/change | `6_3_4_execution_matrix.png` |
| 55 | 6.3.4 | données/config | rate + path docs | K11, doc 8–75 | `6_3_4_data_paths.png` |
| 56 | 6.3.4 | documentation | auth paths | 8–75 | `6_3_4_doc_paths.png` |
| 57 | 6.3.5 | code | triggers and notifications | K18/K19 | `6_3_5_code_triggers.png` |
| 58 | 6.3.5 | test | suspicious notifications | locate test block after 332 | `6_3_5_test_notifications.png` |
| 59 | 6.3.5 | exécution | sandbox mailbox/logs | 4 trigger scenarios | `6_3_5_execution_notifications.png` |
| 60 | 6.3.5 | données/config | dev and SMTP service | K35/K36 | `6_3_5_data_backend.png` |
| 61 | 6.3.5 | documentation | auth paths | 84–106 | `6_3_5_doc_alerts.png` |
| 62 | 6.3.6 | code | MFA + grep absence | K14b/K17 | `6_3_6_code_no_email_factor.png` |
| 63 | 6.3.6 | test | no email auth | 400–414 | `6_3_6_test_no_email.png` |
| 64 | 6.3.6 | exécution | grep search output | exact command in fiche | `6_3_6_execution_search.png` |
| 65 | 6.3.6 | documentation | auth paths | 54–62, 125–134 | `6_3_6_doc_factor.png` |
| 66 | 6.3.7 | code | update and notify | K20/K21 | `6_3_7_code_notify.png` |
| 67 | 6.3.7 | test | credential update notification | 416–455 | `6_3_7_test_notify.png` |
| 68 | 6.3.7 | exécution | SMTP sandbox / dev log | mail after update | `6_3_7_execution_mail.png` |
| 69 | 6.3.7 | données/config | notification backend | K35/K36 | `6_3_7_data_backend.png` |
| 70 | 6.3.7 | documentation | auth paths | 64–75, 110–123 | `6_3_7_doc_update.png` |
| 71 | 6.3.8 | code | generic messages/hash | K14a/K22/K25 | `6_3_8_code_generic.png` |
| 72 | 6.3.8 | tests | login/timing/register | 460–521 | `6_3_8_tests_enum.png` |
| 73 | 6.3.8 | exécution | 10+10 curl timing + pair responses | command fiche | `6_3_8_execution_compare.png` |
| 74 | 6.3.8 | data/config | dummy hash/message | config 122–127 | `6_3_8_data_dummy.png` |
| 75 | 6.3.8 | documentation | auth paths | 37–53, 125–134 | `6_3_8_doc_anti_enum.png` |
| 76 | 6.4.1 | code | token model/issue/TTL | K23/K24/K32 | `6_4_1_code_token_lifecycle.png` |
| 77 | 6.4.1 | test | reset token hash and TTL | 49–60 | `6_4_1_test_token.png` |
| 78 | 6.4.1 | exécution | request, consume, reuse | HTTP scenario fiche | `6_4_1_execution_one_use.png` |
| 79 | 6.4.1 | données/config | token row sans hash | K23/K32 | `6_4_1_data_token.png` |
| 80 | 6.4.1 | documentation | V6.4 report/auth paths | 28–35; 125–134 | `6_4_1_doc_lifecycle.png` |
| 81 | 6.4.2 | code | grep absence | exact terms in fiche | `6_4_2_code_search.png` |
| 82 | 6.4.2 | exécution | no matches terminal | grep command | `6_4_2_execution_no_match.png` |
| 83 | 6.4.2 | données | ORM schema search | `backend/models.py`, no field match | `6_4_2_data_schema.png` |
| 84 | 6.4.3 | code | token/reset/MFA/routes | K23–K26b/K29 | `6_4_3_code_reset.png` |
| 85 | 6.4.3 | tests | four recovery tests | `tests/test_password_recovery.py:49-98` | `6_4_3_tests_reset.png` |
| 86 | 6.4.3 | exécution | known/unknown, finish, replay | curl scenario fiche | `6_4_3_execution_reset.png` |
| 87 | 6.4.3 | data/config | TTL, MFA and SMTP | K32/K35/K36 | `6_4_3_data_config.png` |
| 88 | 6.4.3 | documentation | route paths | auth paths 16–19,125–134 | `6_4_3_doc_reset.png` |
| 89 | 6.4.4 | code | MFA recovery and reenroll | K17/K27/K30/K31 | `6_4_4_code_recovery.png` |
| 90 | 6.4.4 | test | no dedicated test | capture test inventory/search if useful | `6_4_4_no_test.png` |
| 91 | 6.4.4 | exécution | login recovery, email, reenroll | scenario fiche | `6_4_4_execution_reenroll.png` |
| 92 | 6.4.4 | data/config | MFA rows/log | ORM, redacted | `6_4_4_data_mfa.png` |
| 93 | 6.4.4 | documentation | evidence level | V6.4 report 30–48, auth paths 130–132 | `6_4_4_doc_proof_level.png` |
| 94 | 6.4.5 | code | expiry search | grep command in fiche | `6_4_5_code_no_reminders.png` |
| 95 | 6.4.5 | exécution | search result and routes | grep/rg commands | `6_4_5_execution_search.png` |
| 96 | 6.4.5 | données/config | token/session TTL | `backend/config.py:110-116` | `6_4_5_data_ttl.png` |
| 97 | 6.4.5 | documentation | non-applicable rationale | current V6.4 report | `6_4_5_doc_na.png` |
| 98 | 6.4.6 | code | admin guard/route/model | K23/K28/K30 | `6_4_6_code_admin_reset.png` |
| 99 | 6.4.6 | test | admin metadata | 76–85 | `6_4_6_test_metadata.png` |
| 100 | 6.4.6 | exécution | admin vs user request | POST route + email test | `6_4_6_execution_admin.png` |
| 101 | 6.4.6 | data/config | initiator/date/email | token ORM and SMTP sandbox | `6_4_6_data_audit.png` |
| 102 | 6.4.6 | documentation | admin flow | auth paths 18,125–134 | `6_4_6_doc_admin.png` |

**Total proposé : 102 captures** (inclut preuves attendues/non exécutées; ne pas les considérer comme acquises avant prise réelle).

## 7. Conseils de cadrage

- Éditeur avec numéros de ligne visibles, zoom suffisant pour conserver 15–25 lignes et le nom du fichier. Préférer thème clair et contraste élevé pour impression.
- Terminal : cadrer commande, chemin/périmètre, sortie entière et code retour. Pour les tests, cadrer commande pytest complète et résumé.
- Navigateur : montrer URL/route, statut HTTP et message, mais masquer cookies, authorization headers, identifiants, e-mail complet et tout secret.
- Messages : flouter destinataire et lien; masquer entièrement le jeton reset, codes TOTP/secours, hash de mot de passe et QR.
- `.env` n'est jamais une capture. Montrer les noms de variables depuis `.env.example` ou une liste de noms sans valeurs.

## 8. Points non vérifiables

- Base de données MySQL de l'application inaccessible (`localhost:3306` refusé dans l'environnement); aucun schéma ou jeu de comptes déployé n'a été inspecté. Les tests DB intégrés échouent au setup.
- Réseau/DNS vers HIBP indisponible durant la suite; trois assertions échouent sous `HIBP_FAIL_OPEN=True`. Pour preuve de 6.2.12, utiliser un environnement réseau contrôlé ou établir une politique fail-closed.
- Aucun SMTP sandbox n'a été configuré ni confirmé; les journaux du backend `dev` ne prouvent pas la livraison email. 6.3.5, 6.3.7, 6.4.3, 6.4.4 et 6.4.6 restent partielles tant que message réel/reçu n'est pas prouvé.
- Aucun template pour les formulaires généraux; 6.2.6/6.2.7 restent non vérifiables. `/register` et `/login` tentent de rendre des templates absents de l'arborescence.
- L'API/route de changement de mot de passe n'existe pas dans Flask; la fonction métier testée n'est pas une interface utilisateur complète.
- `backend/common_passwords.txt` ne satisfait pas le nombre déclaré/requis : 1 970 mots uniques, 199 conformes à la longueur minimale de 12.
- Aucun test dédié MFA recovery; pas de test HTTP du rôle admin sur route, ni test de mail réel.
- Les recherches d'absence couvrent les fichiers sources spécifiés et ne remplacent pas l'audit de la base de production, des secrets d'environnement ou des binaires générés.

## 9. Bilan des fiches

26 fiches. Exigences sans test existant utile : 6.2.6, 6.2.7, 6.2.10, 6.4.2 (le test existant est obsolète), 6.4.4, 6.4.5; 6.4.6 n'a qu'un test partiel de métadonnées sans contrôle de route. Exigence non respectée : 6.2.4. Exigence N/A : 6.4.5. Exigences partielles/non vérifiables : 6.2.2, 6.2.3, 6.2.6, 6.2.7, 6.2.12, 6.3.1, 6.3.3, 6.3.4, 6.3.5, 6.3.7, 6.3.8, 6.4.3, 6.4.4, 6.4.6.
