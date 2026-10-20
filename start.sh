#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
BACKEND_PORT=5000
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "npm est requis pour lancer l'interface React." >&2
  exit 1
fi

cd "$ROOT_DIR"
FLASK_DEBUG=false PORT="$BACKEND_PORT" "$PYTHON_BIN" -m backend.app &
BACKEND_PID=$!
(cd "$ROOT_DIR/frontend" && npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT") &
FRONTEND_PID=$!

cleanup() {
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Interface React : http://$FRONTEND_HOST:$FRONTEND_PORT"
echo "API Flask      : http://127.0.0.1:$BACKEND_PORT"
wait -n "$BACKEND_PID" "$FRONTEND_PID" || true
