# SecureAuth frontend

SPA React 18 + TypeScript strict + Vite, React Router, React Hook Form/Zod, Vitest/Testing Library/MSW. Tous les formulaires sont en français et les erreurs restent du texte React échappé.

## Installation et lancement

```sh
npm install
npm run dev
npm test
npm run build
npm run lint
```

Configurer `VITE_API_URL` (défaut vide: le serveur Vite relaie `/api`, `/password-reset` et `/mfa/recovery` vers `http://127.0.0.1:5000`) dans `frontend/.env.local`. En déploiement, préférez une origine unique pour SPA et Flask et HTTPS; configurez `VITE_API_URL` seulement si un proxy de production ne fournit pas déjà cette même origine. Ne placez pas de secret ou de token dans cette variable.

## Structure

- `src/api/`: client JSON typé, timeout 10 s et erreurs centralisées.
- `src/auth/`: état d'authentification et garde de routes.
- `src/pages/`, `src/components/`: pages et contrôles partagés.
- `src/config/`: limites alignées sur `backend/config.py`.

Inscription et connexion utilisent maintenant les réponses JSON ajoutées aux routes Flask existantes `/register` et `/login`; le proxy Vite relaie ces appels sans quitter la SPA. Le TOTP ou le code de récupération peut être transmis avec le mot de passe en un seul appel; le session token reste dans le cookie Flask HttpOnly et n'est jamais exposé au JavaScript. La déconnexion utilise le vrai `GET /logout`. Les fonctions sans route ou sans contrat exploitable restent marquées « Backend manquant ». Voir `../docs/FRONTEND_API_INVENTAIRE.md` et `../docs/FRONTEND_API_MANQUANTES.md`.

## Session et limites

Le backend actuel utilise un cookie de session Flask HttpOnly/SameSite=Lax qui contient la session signée et a `Secure=False`. Après un login réussi, React garde l'état utilisateur en mémoire; un rechargement de page perd cet état jusqu'à l'ajout d'une route JSON de session. Aucun token n'est stocké dans Web Storage. Aucun secret MFA ni mot de passe n'est stocké durablement. Le token de réinitialisation est retiré de la barre d'adresse dès l'initialisation de la page et reste uniquement en mémoire le temps de la soumission.

Pour la production: cookie opaque HttpOnly, Secure, SameSite correctement configuré côté serveur, protection CSRF adaptée, origine CORS minimale si les origines diffèrent et CSP restrictive. Une SPA autonome ne peut pas contourner l'absence d'API JSON documentée.
