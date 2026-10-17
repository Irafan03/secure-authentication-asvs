# Mise en conformité OWASP ASVS 5.0.0 : Chapitre V6 (Authentification)

Ce fichier est découpé en **3 tâches à exécuter dans l'ordre**. Chaque tâche est autonome et se termine par un point de contrôle. Ne passe à la tâche suivante que lorsque la précédente est terminée et que les tests passent.

## Règles communes (valables pour les 3 tâches)

- Base-toi uniquement sur le code réel du projet. Ne suppose rien et ne te fie pas aux audits précédents : revérifie dans le code.
- Ne casse pas le comportement existant.
- N'ajoute pas de fonctionnalité qui n'est pas nécessaire pour satisfaire une exigence.
- Les exigences dont la fonctionnalité n'existe pas dans le projet (SMS/OOB, certificats, IdP externe, notifications email, reset de mot de passe…) sont marquées **Non applicable** avec la raison, sans être implémentées.
- Pour chaque correction, indique le fichier et les lignes modifiés.
- Après chaque tâche, mets à jour le fichier `docs/ASVS_PROGRESS.md` (voir le format dans chaque tâche) pour que la tâche suivante puisse reprendre sans relire tout le projet.
- Si une étape bloque (dépendance manquante, test qui échoue, ambiguïté), **ne reste pas bloqué** : note le problème dans `docs/ASVS_PROGRESS.md`, applique la solution la plus simple et sûre, puis continue.
- Objectif de niveau : **L2** (L1 + L2).

---

# TÂCHE 1 sur 3 : Nouvel audit et corrections de niveau 1

## Prompt à donner à Kiro

```
Tu es un expert en sécurité applicative. Exécute la TÂCHE 1 sur 3 de la mise en conformité ASVS 5.0.0 V6 (Authentification). Respecte les règles communes de ce fichier.

### Étape 1 : Audit rapide
Relis le code actuel et liste, avec fichier:ligne, l'état de chaque exigence de niveau 1 :
6.1.1, 6.2.1, 6.2.2, 6.2.3, 6.2.4, 6.2.5, 6.2.6, 6.2.7, 6.2.8, 6.3.1, 6.3.2, 6.4.1, 6.4.2.
Statuts possibles : Respectée / Partielle / Non respectée / Non applicable / Non vérifiable.

### Étape 2 : Corrections
Corrige tout ce qui est partiel ou non respecté. Points déjà identifiés, à confirmer puis corriger :

1. 6.2.5 : supprimer toute règle de composition (types de caractères imposés). Garder min 12 et max 128 caractères.

2. 6.2.4 (et préparation de 6.2.12) : vérifier les mots de passe compromis via l'API Have I Been Pwned en k-anonymity (envoi des 5 premiers caractères du SHA-1 uniquement), avec timeout court, journalisation et comportement défini si l'API est indisponible. Garder en secours une liste locale d'au moins 3 000 mots de passe qui respectent la politique de longueur (donc d'au moins 12 caractères).

3. 6.3.1 : le rate limiting par username seul permet de bloquer le compte d'un autre utilisateur. Le remplacer par :
   - un compteur par adresse IP (seuil dédié),
   - un compteur par couple (username, IP),
   - un délai progressif plutôt qu'un blocage dur du compte,
   - un seuil par username seul bien plus haut, qui ralentit sans bloquer l'utilisateur légitime.
   Vérifier que seuls les échecs sont comptés (success = 0) et que les requêtes SQL ont le bon nombre de paramètres.

4. 6.3.8 (partie temps de réponse) : quand l'utilisateur n'existe pas, exécuter quand même une vérification Argon2 sur un hash factice généré au démarrage avec les mêmes paramètres. Conserver les messages d'erreur génériques.

5. 6.2.6 et 6.2.7 : s'il existe un frontend, vérifier type=password, collage autorisé, autocomplete adapté (current-password / new-password). Sinon, marquer « Non vérifiable côté backend ».

6. 6.3.2 : vérifier qu'aucun compte par défaut (root, admin, sa) n'est créé par le code, les seeds ou les migrations.

### Étape 3 : Tests
Ajoute ou mets à jour les tests automatisés qui prouvent chaque correction :
- mot de passe de 12, 64 et 128 caractères accepté
- mot de passe sans majuscule ni symbole accepté
- mot de passe compromis refusé
- impossibilité de verrouiller le compte d'un autre utilisateur depuis une autre IP
- temps de réponse comparable pour un utilisateur existant et inexistant
Lance les tests et corrige jusqu'à ce qu'ils passent.

### Étape 4 : Point de contrôle
Crée ou mets à jour `docs/ASVS_PROGRESS.md` avec :
- ce qui a été corrigé (exigence, fichier:ligne),
- l'état de chaque exigence de niveau 1,
- les paramètres choisis (seuils du rate limiting, durées, limites de longueur, source des mots de passe compromis),
- les blocages ou décisions prises,
- la liste des fichiers modifiés ou créés.
Termine par un résumé court et arrête-toi. N'enchaîne PAS avec la tâche 2.
```

---

# TÂCHE 2 sur 3 : Corrections de niveau 2 (MFA et contrôles avancés)

## Prompt à donner à Kiro

```
Tu es un expert en sécurité applicative. Exécute la TÂCHE 2 sur 3 de la mise en conformité ASVS 5.0.0 V6 (Authentification). Respecte les règles communes de ce fichier. Commence par lire docs/ASVS_PROGRESS.md pour reprendre là où la tâche 1 s'est arrêtée, puis vérifie rapidement dans le code que les corrections de la tâche 1 sont bien en place.

### Étape 1 : MFA (6.3.3, 6.5.1 à 6.5.5)
Implémente un MFA obligatoire par TOTP :
- secret généré par un CSPRNG, stocké de manière protégée (pas en clair si le projet dispose d'un mécanisme de chiffrement des secrets),
- enrôlement avec QR code, validé par un premier code,
- vérification du code TOTP à la connexion avant toute émission de session ou de jeton,
- code TOTP utilisable une seule fois (refuser le rejeu dans la même fenêtre), durée de 30 secondes,
- codes de récupération : générés par CSPRNG, avec au moins 20 bits d'entropie, à usage unique ; hachés avec un sel (algorithme approuvé pour mots de passe) s'ils ont moins de 112 bits d'entropie,
- le rate limiting de la tâche 1 s'applique aussi à la saisie du code MFA.

### Étape 2 : Liste de mots contextuels (6.2.11 et 6.1.2)
Crée une liste de mots spécifiques au contexte (nom du projet, de l'organisation, du produit, des services, et leurs variantes courantes). Applique-la à la création et au changement de mot de passe : refuser les mots de passe qui contiennent ces mots (insensible à la casse, y compris avec ajout de chiffres ou symboles simples).

### Étape 3 : Voies d'authentification (6.3.4 et 6.1.3)
Recense toutes les voies d'authentification (login, API, endpoints secondaires, anciennes versions). Vérifie qu'aucune ne contourne le MFA ni le rate limiting, et corrige si c'est le cas.

### Étape 4 : Récupération de compte (6.4.3 et 6.4.4)
Si une fonction de reset ou de récupération existe, elle ne doit jamais contourner le MFA. Si elle n'existe pas, ne la crée pas : marque 6.4.3, 6.4.4, 6.4.5 et 6.4.6 comme « Non applicable : fonction absente ».

### Étape 5 : Énumération via l'inscription (6.3.8)
Répondre par un message générique identique que le nom d'utilisateur ou l'email existe déjà ou non. Si le projet n'a pas d'envoi d'email, applique la meilleure atténuation possible et documente la limite restante.

### Étape 6 : Mots de passe compromis (6.2.12)
Vérifie que le contrôle HIBP de la tâche 1 est appliqué à l'inscription ET au changement de mot de passe.

### Étape 7 : Tests
Ajoute les tests automatisés :
- connexion impossible sans second facteur
- rejeu d'un code TOTP refusé
- code de récupération utilisable une seule fois
- code TOTP expiré refusé
- mot de passe contenant un mot contextuel refusé
- message identique à l'inscription que le compte existe ou non
- aucune voie d'authentification ne contourne le MFA
Lance les tests et corrige jusqu'à ce qu'ils passent.

### Étape 8 : Point de contrôle
Mets à jour docs/ASVS_PROGRESS.md avec : ce qui a été fait dans cette tâche (exigence, fichier:ligne), l'état des exigences L2, les paramètres choisis (durée TOTP, nombre de codes de récupération, liste contextuelle), les blocages, les fichiers modifiés ou créés.
Termine par un résumé court et arrête-toi. N'enchaîne PAS avec la tâche 3.
```

---

# TÂCHE 3 sur 3 : Documentation de conformité et code propre

## Prompt à donner à Kiro

```
Tu es un expert en sécurité applicative. Exécute la TÂCHE 3 sur 3 de la mise en conformité ASVS 5.0.0 V6 (Authentification). Respecte les règles communes de ce fichier. Commence par lire docs/ASVS_PROGRESS.md, puis revérifie dans le code l'état réel de chaque exigence : la documentation doit refléter exactement le code actuel.

### Étape 1 : Documentation de conformité
Crée le fichier docs/ASVS_V6_CONFORMITE.md (et référence-le dans README.md) contenant :

1. Résumé : niveau ASVS atteint (L1 ou L2), nombre d'exigences par statut (Respectée / Non applicable / Non vérifiable / Non respectée), date de l'analyse.

2. Un tableau complet des 47 exigences V6.1 à V6.8 :
   | Exigence | Niveau | Statut | Où elle est respectée (fichier:fonction:ligne) | Comment c'est implémenté | Comment la tester |
   Aucune exigence ne doit être omise. Pour chaque « Non applicable » ou « Non vérifiable », donne la raison. Aucune exigence n'est marquée « Respectée » sans preuve précise dans le code.

3. Les paramètres de sécurité : seuils du rate limiting, durées, algorithme de hachage et ses paramètres, longueurs min/max, source de la liste de mots de passe compromis, paramètres TOTP.

4. La liste des voies d'authentification (6.1.3) et la liste de mots contextuels utilisée (6.1.2).

5. La documentation du rate limiting (6.1.1) : comment il fonctionne, comment il évite le blocage malveillant d'un compte.

6. Les limites connues et les points qui restent à la charge de l'infrastructure ou du frontend.

### Étape 2 : Code propre
Rends le code plus propre sans changer le comportement :
- noms explicites,
- fonctions courtes,
- pas de duplication,
- gestion d'erreurs cohérente,
- constantes de sécurité centralisées dans un seul fichier de configuration,
- commentaires utiles uniquement.
Relance tous les tests : ils doivent tous passer.

### Étape 3 : Sortie finale
Termine par un court résumé :
- ce qui a été corrigé au total,
- ce qui reste non respecté (avec la raison),
- le niveau ASVS atteint,
- la liste des fichiers modifiés ou créés,
- le résultat des tests.
```

---

## Option : viser le niveau L3

À ajouter dans la tâche 2 si besoin : notifications des tentatives suspectes et des changements d'identifiants (6.3.5, 6.3.7), révocation des facteurs perdus (6.5.6), TOTP vérifié avec une source de temps serveur fiable (6.5.8), et authentification matérielle de type passkey/WebAuthn (6.3.3 en L3). Cela demande en général un service d'envoi d'emails ou de notifications.