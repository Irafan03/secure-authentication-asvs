# Inventaire API pour le frontend

État vérifié dans `backend/app.py`, `backend/auth_login.py`, `backend/auth_register.py`, `backend/auth_mfa.py`, `backend/password_recovery.py` et `backend/config.py`. L'application est actuellement une interface Flask à formulaires. Il n'existe pas de préfixe d'API REST général ni de configuration CORS. Les réponses HTML/redirections ne sont pas des contrats JSON consommables par une SPA.

## Routes réellement exposées

| Méthode / chemin | Requête | Réponse réelle | Authentification |
|---|---|---|---|
| GET, POST `/register` | POST accepte formulaire URL-encoded historique ou JSON `{username,email,password,password_confirm}` | JSON succès `201 {success:true,message}`; échec `400 {success:false,errors:string[]}`. Le flux HTML historique conserve flash/redirection; le chemin JSON ne rend aucun template | aucune |
| GET, POST `/login` | POST accepte formulaire HTML historique ou JSON `{username,password,totp_code?,recovery_code?}` | JSON succès `{success:true,user:{id,username,email,role},mfa_enrollment_required?}`; identifiants invalides `401 {success:false,errors}`; facteur manquant `200 {success:false,mfa_required:true,errors}`; blocage `423 {success:false,errors,locked_until:ISO8601}`. Le jeton métier n'est pas renvoyé en JSON: la session Flask le place dans son cookie | cookie de session Flask HttpOnly, SameSite=Lax; Secure est actuellement False |
| GET `/dashboard` | — | HTML ou redirection | cookie Flask, session métier validée côté serveur |
| GET, POST `/mfa/enroll` | formulaire `totp_code` au POST | GET renvoie HTML (secret, `qr_code_uri`, `recovery_codes`); POST redirige avec message flash | cookie Flask |
| GET `/logout` | — | redirection | cookie Flask; invalide la session métier; appelé par le frontend via proxy Vite |
| POST `/api/validate-password` | JSON `{password, username?}` | JSON `{valid, errors}` | aucune; contrôle de sécurité côté serveur |
| GET, POST `/password-reset` | POST JSON ou formulaire `{identifier}` | JSON `{success, message}` neutre; GET renvoie HTML | aucune |
| GET, POST `/password-reset/confirm` | token en query sur GET; POST JSON/form `{token,new_password,totp_code?,recovery_code?}` | GET HTML avec `Cache-Control: no-store`, `Referrer-Policy: no-referrer`; POST JSON `{success,message}` ou `{success,errors}` (400) | aucune |
| POST `/admin/users/<user_id>/password-reset` | aucun corps | JSON `{message}`; 403 JSON `{error}` | cookie Flask + rôle admin |
| POST `/mfa/recovery/request` | aucun corps | JSON `{message}` neutre | cookie Flask |
| GET, POST `/mfa/recovery/confirm` | token en query sur GET; POST `{token,current_password}` | HTML puis JSON `{success,message}` | cookie Flask |

Aucun endpoint d'activité/notifications n'est exposé. Les routes `/register` et `/login` prennent désormais aussi en charge le JSON pour la SPA, tout en gardant les formulaires HTML historiques. Les réponses JSON évitent le rendu des templates Flask manquants; le login accepte TOTP ou code de récupération dans le même appel et ne place pas le mot de passe en session pour un challenge intermédiaire. Aucun endpoint n'est exposé pour enrôlement MFA, changement mot de passe/email/nom ou consultation de session. La déconnexion reste GET `/logout`.

## Fonctions métier

| Fonction | Exposée | Détail |
|---|---|---|
| `register_user` | Oui, `/register` | formulaire HTML ou JSON; JSON retourne success/message/errors |
| `authenticate_user` | Oui, `/login` | formulaire HTML ou JSON; le JSON ne retourne pas session_token et accepte les facteurs dans le même envoi |
| `change_password` | Non | fonction Python seulement |
| `change_email` | Non | fonction Python seulement |
| `change_username` | Non | fonction Python seulement |
| `enroll_mfa` | Oui, indirectement GET `/mfa/enroll` | secret, `qr_code_uri`, `recovery_codes` dans HTML et session Flask |
| `validate_mfa_enrollment` | Oui, indirectement POST `/mfa/enroll` | formulaire puis redirection |
| `verify_totp_code` | Non directement | interne à authentification/enrôlement/réinitialisation |
| `verify_recovery_code` | Non directement | interne; pas de code de récupération au login HTML |
| `logout_user` | Oui, indirectement GET `/logout` | session invalide puis redirection |
| `validate_password` | Oui, POST `/api/validate-password` | `{valid,errors}` |
| `request_password_reset` | Oui, POST `/password-reset`; aussi route admin | résultat public neutre |
| `complete_password_reset` | Oui, POST `/password-reset/confirm` | contrôle TOTP ou code de récupération si MFA actif |
| récupération perte MFA | Oui, `/mfa/recovery/request` et `/mfa/recovery/confirm` | nécessite une session authentifiée |

## Configuration pertinente et session

`PASSWORD_MIN_LENGTH=12`, `PASSWORD_MAX_LENGTH=128`, `SESSION_DURATION=8h`, expiration reset `20 min`, TOTP 6 chiffres/30 secondes. Le token métier est conservé dans la session Flask (cookie signé HttpOnly, SameSite=Lax), et non renvoyé comme cookie métier dédié; le paramètre `SESSION_COOKIE_SECURE` est actuellement désactivé. Pas de CORS configuré. En production, servir la SPA et Flask sous même origine ou ajouter une origine CORS explicite et activer Secure sous HTTPS; utiliser une session serveur opaque en cookie HttpOnly/Secure/SameSite et ne jamais conserver un token dans le navigateur accessible au JS.

## En-têtes recommandés

Servir une CSP restrictive, adaptée aux assets Vite (`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' <origine-api>; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`), ainsi que `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` et HSTS en HTTPS. Ces en-têtes ne sont pas imposés par le frontend.
