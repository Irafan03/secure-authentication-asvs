# Interface SecureAuth

Application React 18, TypeScript strict et Vite. Les formulaires et parcours d'authentification sont en français.

## Lancer

À la racine du dépôt, `./start.sh` lance React sur `http://127.0.0.1:5173` et l'API Flask sur `http://127.0.0.1:5000`. Pour lancer l'interface seule :

```sh
npm ci
npm run dev
```

Le proxy Vite transmet les appels JSON à Flask en conservant les cookies `HttpOnly`. Ne définissez `VITE_API_URL` que si l'API est réellement servie sur une autre origine.

## Parcours inclus

- Inscription et connexion, y compris code TOTP ou code de récupération.
- État de session rechargé via `GET /api/auth/session`.
- Activation MFA par QR code, confirmation TOTP, affichage unique des codes de récupération et désactivation avec réauthentification.
- Changement de mot de passe, demande et confirmation de réinitialisation.
- Récupération MFA via lien sécurisé.

Aucun mot de passe, token, secret MFA ou code de récupération n'est enregistré dans Web Storage. Les codes de récupération et le secret MFA restent en mémoire le temps de l'enrôlement.

## Vérifications

```sh
npm test
npm run build
npm run lint
```
