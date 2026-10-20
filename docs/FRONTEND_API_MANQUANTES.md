# Limites restantes du frontend

Les parcours d'authentification, de mot de passe et de MFA utilisés par l'interface sont exposés en JSON, y compris la demande de récupération MFA sans session, protégée contre l'énumération, puis confirmée par lien temporaire et mot de passe. Les fonctions sans interface et endpoint sont les changements de nom/email, l'historique détaillé d'activité et une console d'administration complète; ces parcours ne sont pas présentés comme disponibles dans la SPA.

Voir [l'inventaire des contrats API](FRONTEND_API_INVENTAIRE.md) pour les routes effectivement exposées.

Le fonctionnement réel de l'authentification nécessite une base MySQL configurée dans `.env`. Sans accès à MySQL, l'API démarre mais les opérations de compte ne peuvent pas persister. Les tests `tests/test_api_contracts.py` simulent les dépendances métier et vérifient les contrats HTTP indépendamment d'une base.
