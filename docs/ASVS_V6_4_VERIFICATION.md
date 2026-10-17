# Vérification ASVS 5.0.0 — V6.4

Audit du code présent dans le dépôt avant implémentation, puis revue après changements. Les lignes ci-dessous sont à confirmer avec `nl -ba` au moment du rapport, car elles évoluent avec les modifications.

## Phase 0 — Découverte

- Python, Flask, SQLAlchemy et MySQL; le dépôt contient aussi un ancien chemin `mysql.connector`.
- Authentification : `backend/app.py`, `backend/auth_login.py`, `backend/auth_register.py`, `backend/auth_mfa.py`, `backend/models.py`, `backend/notifications.py`, `backend/config.py`.
- Modèles : `User.role` comprend `user` et `admin`. Aucun outil de migration n'est présent ; les nouveaux modèles sont créés par `init_db_orm()` / SQLAlchemy `create_all`.
- Routes initiales : `GET /`, `GET|POST /register`, `GET|POST /login`, `GET /dashboard`, `GET|POST /mfa/enroll`, `GET /logout`, `POST /api/validate-password`, `GET /test`.
- Routes V6.4 ajoutées : `GET|POST /password-reset`, `GET|POST /password-reset/confirm`, `POST /admin/users/<user_id>/password-reset`, `POST /mfa/recovery/request`, `GET|POST /mfa/recovery/confirm`.
- Aucun répertoire de templates n'est présent dans l'inventaire ; les nouveaux formulaires sont rendus directement par Flask et acceptent aussi les requêtes JSON POST.
- Tests pytest présents dans `tests/`, notamment pour les niveaux 1, 2 et V6.3.

## Phase 1 — Vérification avant changement

Les fichiers ont été recherchés avec `rg -n -i 'hint|password_hint|security_question|question|answer|memorable' --glob '*.py' --glob '*.html' --glob '*.sql' .` et `rg --files`. Aucun champ ou flux de connaissance n'a été trouvé. La base de données réelle n'a pas été inspectée ; la connexion n'est pas une preuve de schéma.

| Exigence | État initial | Preuve et raison |
|---|---|---|
| 6.4.1 | ➖ Non applicable | `backend/auth_register.py:366` (`register_user`) reçoit un mot de passe choisi ; `backend/create_admin.py:22,50-87` valide et persiste celui fourni par l'opérateur. Aucune génération de mot de passe/code d'activation trouvée. |
| 6.4.2 | ✅ Respectée (code) | La recherche `rg` ci-dessus n'a rien trouvé ; schéma réel non inspecté. |
| 6.4.3 | ❌ Non respectée | Avant changement, `backend/app.py:50-229` ne contenait aucune route de reset et aucun service correspondant n'existait. |
| 6.4.4 | ⚠️ Partielle | `backend/auth_mfa.py:218` (`verify_recovery_code`) consomme un code unique et `backend/app.py:148` expose l'enrôlement, mais pas de parcours documenté de récupération/réenrôlement. |
| 6.4.5 | ➖ Non applicable | `backend/models.py:67-76` fixe une échéance aux sessions ; TOTP expire par période dans `backend/config.py:81-85`, mais aucun authentificateur utilisateur n'expire avec rappel. |
| 6.4.6 | ❌ Non respectée | `backend/models.py:34` définit le rôle `admin`, sans route serveur de reset dans l'inventaire initial `backend/app.py:50-229`. |

## Phase 2 — Mesures ajoutées

- `PasswordResetToken` conserve uniquement SHA-256 du jeton à haute entropie, dates, usage, motif et initiateur. Expiration par défaut : 20 minutes. Les demandes antérieures actives sont invalidées ; les expirées sont nettoyées lors de l'émission.
- Demande générique HTTP 200, travail Argon2 factice sur les deux chemins, limitation réutilisant `check_rate_limit` et `record_login_attempt`, notification via `get_notification_service`.
- Finalisation à usage unique, comparaison constante, validation avec `validate_password`, refus du mot de passe courant, exigence TOTP/code de récupération si MFA activé, invalidation de toutes les sessions et notification de changement.
- Le reset admin est protégé par le rôle serveur, cible le compte par ID, n'accepte ni mot de passe ni jeton fourni, et garde l'acteur/cible/horodatage dans le registre de jeton et les logs.
- La récupération MFA requiert une session qui a passé le facteur actuel (le code de récupération permet l'accès en cas de perte du TOTP), un lien envoyé à l'adresse enregistrée et le mot de passe courant. Elle supprime les anciens secrets/codes, invalide les sessions, notifie l'utilisateur et limite le prochain login au réenrôlement.
- Les nouveaux accès DB de ces parcours utilisent SQLAlchemy. Le dépôt ne possède pas de système de migration ; `init_db_orm()` crée les nouvelles tables via le modèle ORM.

## Phase 3–4 — Vérification et statut après changement

Le statut de livraison dépend de la configuration effective des notifications : `get_notification_service()` sélectionne le backend dev par défaut ; celui-ci journalise les messages et ne les envoie pas à l'utilisateur. Configurer `NOTIFICATION_BACKEND=email`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_USE_TLS` ou `SMTP_USE_SSL`, `NOTIFICATION_EMAIL_FROM`, ainsi que `PASSWORD_RESET_URL_BASE` et `APP_PUBLIC_BASE_URL` avec des URL HTTPS publiques. Tant que l'envoi réel n'est pas configuré, aucun flux qui dépend du mail n'est marqué « Respectée ».

| Exigence | État après changement | Limite constatée |
|---|---|---|
| 6.4.1 | ✅ Respectée pour les jetons de récupération | Pas de secret initial de mot de passe généré par l'application. |
| 6.4.2 | ✅ Respectée dans le code relu | La base effective reste à contrôler avec le schéma de déploiement. |
| 6.4.3 | ⚠️ Partielle jusqu'à SMTP effectif | Implémentation présente ; la route dépend de l'envoi de lien et le backend dev ne délivre pas de mail. Le SMTP synchrone peut aussi révéler une différence temporelle. |
| 6.4.4 | ⚠️ Partielle jusqu'à SMTP effectif | Chemin de récupération MFA implémenté ; dépend du lien email. La preuve suppose que l'utilisateur a conservé son code de récupération ou sa session MFA. |
| 6.4.5 | ➖ Non applicable | Aucun authentificateur expirant/rappel ajouté. |
| 6.4.6 | ⚠️ Partielle jusqu'à SMTP effectif | Contrôle admin et émission du reset implémentés ; l'utilisateur ne reçoit pas le lien si la notification n'est pas réellement délivrée. |

Vérification exécutée : `.venv/bin/python -m compileall -q backend/app.py backend/auth_login.py backend/auth_mfa.py backend/models.py backend/password_recovery.py backend/config.py backend/notifications.py tests/test_password_recovery.py` a terminé sans erreur. `.venv/bin/pytest -q tests/test_password_recovery.py` : **4 passed**. La commande `.venv/bin/pytest -q` : **47 passed, 3 failed, 30 errors**. Les 30 erreurs de setup viennent de l'impossibilité de joindre MySQL `localhost:3306` dans l'environnement. Les 3 échecs de tests existants attendent le refus d'un mot de passe via HIBP ; l'appel réseau à `api.pwnedpasswords.com` échoue sans DNS, et la configuration `HIBP_FAIL_OPEN=True` accepte alors le mot de passe. Aucun service de base de données ni d'accès réseau n'était disponible pour valider ces suites.

## Guide de captures d'écran pour le rapport

Utiliser une base et des comptes de démonstration, un SMTP de test, une adresse contrôlée, et des jetons synthétiques. Masquer les adresses, identifiants de session et jetons avant de joindre les captures. Ne jamais capturer un mot de passe ou le contenu complet d'un vrai email.

1. **Inventaire du code** : capture de `backend/models.py` montrant `PasswordResetToken` et ses champs; puis `backend/config.py` pour le TTL.
2. **Demande neutre** : envoyer une demande pour un compte de test et une adresse inexistante ; capturer deux réponses HTTP 200 identiques, sans inclure de secret.
3. **Notification de reset** : capture du client SMTP de test avec sujet et destinataire masqué ; ne montrer qu'un jeton masqué. Si backend dev, capture des variables de configuration et indiquer que cela ne prouve pas une livraison réelle.
4. **MFA obligatoire** : tenter de finaliser un reset MFA avec un jeton valide mais sans second facteur, puis avec un TOTP/code de récupération valide ; capturer le refus puis le succès, en masquant les valeurs.
5. **Usage unique et sessions** : réutiliser le lien consommé et montrer le refus ; montrer que l'ancienne session ne permet plus d'accéder au tableau de bord.
6. **Initiation admin** : connecter un administrateur de test, déclencher le reset d'un utilisateur, capturer la réponse sans secret et le message reçu côté utilisateur ; montrer aussi le 403 d'un compte `user`.
7. **Récupération MFA** : utiliser une session obtenue avec code de récupération, confirmer via email et mot de passe, puis montrer les anciens codes refusés et le prochain login limité à l'enrôlement MFA.
8. **Tests** : capture terminal avec la commande réellement exécutée et son résumé pytest. Ne pas remplacer les échecs par un résultat attendu.

## Résumé initial

Avant changement : 1 ✅, 1 ⚠️, 2 ❌, 2 ➖, 0 ❓. Après changement : 2 ✅, 3 ⚠️, 1 ➖, 0 ❌, 0 ❓ (les statuts ⚠️ passent à ✅ uniquement après preuve de livraison mail réelle et revue temporelle).
