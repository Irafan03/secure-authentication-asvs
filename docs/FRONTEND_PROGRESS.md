# Avancement du frontend

## État

- Phase 0 terminée : routes et contrats réels consignés dans `FRONTEND_API_INVENTAIRE.md`.
- Phase 1 terminée : arborescence et limites d'intégration décrites dans `frontend/README.md`.
- Phase 2 : base React/TypeScript, client API et pages de parcours créés. Inscription et connexion appellent JSON sur les routes Flask réelles `/register` et `/login`; déconnexion utilise `GET /logout`. Les fonctions sans route sont identifiées comme manquantes; aucun endpoint fictif n'est appelé.
- Phase 3 : tests Vitest/RTL/MSW ajoutés; dernière exécution: 10 tests passent, build TypeScript/Vite réussi, ESLint réussi. Revue statique: aucun `dangerouslySetInnerHTML`, stockage Web Storage, journal console ou blocage du collage dans le frontend.
- Phase 4 : documentation initiale créée.

## Blocage constaté et solution sûre

Le backend n'expose pas d'API de session, de changement de profil, d'enrôlement MFA ou d'activité. Le traceback `TemplateNotFound: register.html` montrait que les erreurs de formulaire HTML tentaient de rendre un template absent. Pour préserver les routes et formulaires historiques tout en corrigeant cette intégration, `/register` et `/login` retournent maintenant JSON quand la requête le demande explicitement; les réponses JSON ne passent jamais par les templates et le login ne conserve pas le mot de passe pour un challenge intermédiaire. Aucun nouvel endpoint n'a été ajouté.

Modification backend: adaptation JSON conditionnelle des routes `/register` et `/login` existantes, nécessaire pour éviter le rendu des templates absents et fournir les réponses que la SPA consomme. Le comportement HTML historique est gardé. Pas de modification CORS; en local, Vite relaie les appels vers Flask.

Initialement, l'accès réseau empêchait l'installation npm. Après autorisation, les dépendances ont été installées et Vite aligné en version 5 avec Vitest afin d'éliminer le conflit de types. Le mode de développement Vite relaie les routes API vers Flask pour éviter CORS en local.

## Démarrage local vérifié

Serveurs démarrés: React/Vite sur `http://localhost:5173/`, Flask sur `http://127.0.0.1:5000/`. Routes SPA servies par Vite. Proxy local pour `/login`, `/register`, `/logout` et les routes JSON existantes. Tests/build/lint passent. La page d'accueil historique Flask `/` peut encore répondre 500 car le template `index.html` n'existe pas dans `backend/templates`; la SPA sert sa propre page d'accueil.
