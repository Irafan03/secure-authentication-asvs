# Contrats de l'API SecureAuth

L'interface React appelle les routes JSON de `backend/app.py`. Les opérations qui modifient un compte s'appuient sur la session émise dans le cookie opaque `secureauth_session` (`HttpOnly`, `SameSite=Lax`, `Secure` configurable).

| Méthode | Route | Authentification | Résultat |
|---|---|---|---|
| `GET` | `/health` | aucune | État du service |
| `POST` | `/register` | aucune | Crée un compte; `201` en cas de succès |
| `POST` | `/login` | aucune | Connexion avec mot de passe, TOTP ou code de récupération; MFA manquant retourne `mfa_required` |
| `GET` | `/api/auth/session` | cookie | Utilisateur et état MFA; `401` si absent ou expiré |
| `POST` | `/api/auth/logout` | facultative | Invalide la session et supprime le cookie |
| `POST` | `/api/validate-password` | aucune | Valide un mot de passe côté serveur |
| `POST` | `/api/account/password` | cookie | Change le mot de passe après vérification du mot de passe actuel |
| `POST` | `/api/account/mfa/enrollment` | cookie | Retourne provisoirement secret TOTP, URI QR et codes de récupération |
| `POST` | `/api/account/mfa/enrollment/confirm` | cookie | Vérifie le premier code TOTP et active la MFA |
| `POST` | `/api/account/mfa/disable` | cookie | Désactive la MFA après vérification du mot de passe et d'un facteur |
| `POST` | `/password-reset` | aucune | Demande un lien avec une réponse publique neutre |
| `POST` | `/password-reset/confirm` | aucune | Réinitialise le mot de passe avec le token et le facteur MFA si activé |
| `POST` | `/mfa/recovery/request` | aucune | Demande un lien MFA par identifiant, avec réponse neutre anti-énumération |
| `POST` | `/mfa/recovery/confirm` | lien temporaire + mot de passe | Confirme la récupération, invalide les sessions et retire le cookie |
| `POST` | `/admin/users/<id>/password-reset` | cookie admin | Demande un lien de réinitialisation pour un utilisateur |

Les secrets MFA et mots de passe ne sont jamais écrits dans Web Storage ni dans le cookie d'authentification. Les codes de récupération sont affichés une fois pendant l'enrôlement et stockés hachés côté serveur.
