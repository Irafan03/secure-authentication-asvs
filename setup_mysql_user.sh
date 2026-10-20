#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Fichier .env introuvable : $ENV_FILE" >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

if [[ "${DB_NAME:-}" != "secure_auth_db" || ! "${DB_USER:-}" =~ ^secure_auth_[a-f0-9]{8}$ || ! "${DB_PASSWORD:-}" =~ ^[A-Za-z0-9!_+-]{48}$ ]]; then
  echo "Les paramètres DB_NAME, DB_USER ou DB_PASSWORD de .env ne correspondent pas aux identifiants générés." >&2
  exit 1
fi

if (( EUID == 0 )); then
  MYSQL_CMD=(mysql --protocol=socket --user=root)
else
  MYSQL_CMD=(sudo mysql --protocol=socket --user=root)
fi

# Prefer socket authentication; prompt for the MySQL root password if it is required.
if ! "${MYSQL_CMD[@]}" --batch --skip-column-names --execute 'SELECT 1' >/dev/null 2>&1; then
  MYSQL_CMD+=(--password)
fi

"${MYSQL_CMD[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "Base $DB_NAME et utilisateur MySQL créés. Le mot de passe reste dans .env."
