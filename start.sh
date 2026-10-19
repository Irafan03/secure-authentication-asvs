#!/bin/bash
set -euo pipefail

MODE="${1:-dev}"
PORT="${PORT:-8080}"

<<<<<<< HEAD
echo "================================================"
echo "  SecureAuth ASVS - Démarrage de l'application"
echo "================================================"
echo ""

# Vérifier que Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Erreur: Python 3 n'est pas installé"
    exit 1
fi

echo "✅ Python $(python3 --version) détecté"

# Vérifier que l'environnement virtuel existe
if [ ! -d ".venv" ]; then
    echo ""
    echo "⚠️  Environnement virtuel non trouvé. Création..."
    python3 -m venv .venv
    echo "✅ Environnement virtuel créé"
fi

# Activer l'environnement virtuel
echo ""
echo "🔄 Activation de l'environnement virtuel..."
source .venv/bin/activate

# Installer/mettre à jour les dépendances
echo ""
echo "📦 Installation des dépendances..."
pip install -q -r requirements.txt
echo "✅ Dépendances installées"

# Charger les variables d'environnement si .env existe
if [ -f ".env" ]; then
    echo ""
    echo "🔐 Chargement des variables d'environnement..."
    export $(cat .env | grep -v '^#' | xargs)
    echo "✅ Variables d'environnement chargées"
else
    echo ""
    echo "⚠️  Fichier .env non trouvé"
    echo "   Copiez .env.example en .env et configurez-le:"
    echo "   cp .env.example .env"
    echo ""
    read -p "Voulez-vous continuer avec la configuration par défaut? (o/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
        exit 1
    fi
fi

# Vérifier la connexion MySQL
echo ""
echo "🔍 Vérification de la connexion MySQL..."
if python3 -c "from backend.database import get_connection; get_connection().close()" 2>/dev/null; then
    echo "✅ Connexion MySQL réussie"
else
    echo "❌ Erreur: Impossible de se connecter à MySQL"
    echo ""
    echo "Vérifiez les paramètres dans .env:"
    echo "  - DB_HOST"
    echo "  - DB_PORT"
    echo "  - DB_NAME"
    echo "  - DB_USER"
    echo "  - DB_PASSWORD"
    exit 1
fi

# Initialiser la base de données
echo ""
echo "🗄️  Initialisation de la base de données..."
python3 -c "from backend.database import init_db; init_db()" 2>/dev/null || echo "⚠️  Tables déjà créées"
echo "✅ Base de données prête"

# Démarrer l'application selon le mode
echo ""
echo "================================================"
if [ "$MODE" = "prod" ]; then
    echo "🚀 Démarrage en mode PRODUCTION sur le port $PORT"
    echo "================================================"
    echo ""
    
    # Vérifier que Gunicorn est installé
    if ! command -v gunicorn &> /dev/null; then
        echo "📦 Installation de Gunicorn..."
        pip install gunicorn
    fi
    
    echo "🌐 Application disponible sur: http://0.0.0.0:$PORT"
    echo ""
    gunicorn -w 4 -b 0.0.0.0:$PORT backend.app:app
else
    echo "🔧 Démarrage en mode DÉVELOPPEMENT sur le port $PORT"
    echo "================================================"
    echo ""
    echo "🌐 Application disponible sur: http://localhost:$PORT"
    echo ""
    echo "⚠️  Mode développement uniquement !"
    echo "   Pour la production, utilisez: ./start.sh prod"
    echo ""
    python3 -m backend.app
=======
if [ "$MODE" = "prod" ]; then
    exec uvicorn app:app --host 0.0.0.0 --port "$PORT" --workers "${WORKERS:-4}"
>>>>>>> 68f20a7 (frontend)
fi

exec uvicorn app:app --reload --host 0.0.0.0 --port "$PORT"
