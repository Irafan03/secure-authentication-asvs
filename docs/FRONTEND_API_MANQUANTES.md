# API backend manquantes pour une SPA

Le backend expose aujourd'hui des formulaires HTML Flask. Le frontend React ne les appelle pas comme s'il s'agissait d'API JSON. Les routes ci-dessous sont des contrats proposés, à implémenter côté backend avant activation. Toutes les routes sensibles doivent utiliser la session serveur cookie HttpOnly/Secure/SameSite; réponses JSON sans secrets superflus, erreurs structurées et rate limiting serveur.

| Fonctionnalité | Contrat proposé | Réponses |
|---|---|---|
| Challenge MFA en deux étapes | `POST /api/auth/login` puis `POST /api/auth/login/mfa` | Les routes existantes `POST /login` acceptent désormais JSON `{username,password,totp_code?,recovery_code?}` dans un seul appel. Succès: `{success:true,user}` + cookie Flask; échec générique `401`; facteur manquant `200 {success:false,mfa_required:true,errors}`; verrouillage `423 {success:false,errors,locked_until}`. Un challenge temporaire indépendant du mot de passe reste souhaitable pour permettre une saisie MFA en second temps sans ressaisir le mot de passe. |
| Inscription JSON | `POST /api/auth/register` (proposition seulement si un préfixe uniforme est requis) | La route existante `POST /register` accepte désormais JSON `{username,email,password,password_confirm}` → `201 {success:true,message}` ou `400 {success:false,errors}`. Aucun endpoint supplémentaire n'est nécessaire pour le frontend actuel. |
| Session courante | `GET /api/auth/session` | `200 {authenticated:true,user:{id,username,email,role}}`; `401 {authenticated:false}`. Le contexte React perd son état au rechargement tant que cette route n'existe pas. |
| Déconnexion JSON (optionnel) | `POST /api/auth/logout` | `200 {success:true}` et suppression/invalidation de session. Le frontend utilise actuellement le vrai `GET /logout`. |
| Enrôlement MFA | `POST /api/account/mfa/enrollment` sans corps | `200 {secret,qr_code_uri}` (aucun code de récupération avant confirmation) |
| Confirmer enrôlement MFA | `POST /api/account/mfa/enrollment/confirm` JSON `{totp_code}` | `200 {success:true,recovery_codes:string[]}` à afficher une seule fois; `400 {success:false,errors:string[]}` |
| Changer mot de passe | `POST /api/account/password` JSON `{current_password,new_password}` | `200 {success:true,message}`; `400 {success:false,errors:string[]}`; notif envoyée côté serveur |
| Changer email | `PATCH /api/account/email` JSON `{current_password,new_email}` | `200 {success:true,message}`; notification aux deux adresses |
| Changer nom utilisateur | `PATCH /api/account/username` JSON `{current_password,new_username}` | `200 {success:true,message}` |
| Notifications / activité | `GET /api/account/security-activity?limit=50` | `200 {items:[{id,type,created_at,summary}]}` sans secret ni données sensibles inutiles |
| MFA perdu avant connexion | `POST /api/auth/mfa/recovery` JSON `{username}` | `200 {success:true,message}` même si compte absent; lien envoyé selon procédure serveur |

Déjà exposés et appelés par le frontend: `POST /register` JSON, `POST /login` JSON (MFA inclus au même appel), `POST /api/validate-password` JSON `{password,username?}` → `{valid,errors}`; `POST /password-reset` JSON `{identifier}` → `{success,message}` neutre; `POST /password-reset/confirm` JSON `{token,new_password,totp_code?,recovery_code?}` → `{success,message}` ou `{success,errors}`. Les formulaires HTML historiques de `/register` et `/login` sont conservés.

L'enrôlement MFA, les réglages de compte, l'historique et l'endpoint de consultation de session restent indisponibles côté SPA. Authentification et inscription utilisent maintenant les réponses JSON sur les routes Flask existantes; leurs formulaires HTML historiques restent disponibles. L'action administrateur existante est `POST /admin/users/<id>/password-reset` mais exige une session Flask; un endpoint de session/administration reste à ajouter si nécessaire.
