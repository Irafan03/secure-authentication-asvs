# Interface web

SecureAuth utilise une SPA React dans `frontend/` et une API JSON Flask dans `backend/app.py`. Les pages Jinja et leurs ressources dédiées ont été retirées; React est l'interface de référence.

Lancez `./start.sh` à la racine pour démarrer l'interface sur `http://127.0.0.1:5173` et l'API sur `http://127.0.0.1:5000`. Configurez MySQL dans `.env` pour activer les opérations qui écrivent des comptes et sessions.

Les parcours disponibles dans la SPA sont l'inscription, la connexion avec MFA, la récupération et le changement de mot de passe, la gestion MFA, ainsi que la récupération MFA. Les endpoints correspondants sont décrits dans [l'inventaire API](docs/FRONTEND_API_INVENTAIRE.md).
