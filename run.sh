#!/usr/bin/env bash
# Start the file server manually on Ubuntu. Run: ./run.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing .env. Copy .env.example to .env and configure it first." >&2
  exit 1
fi

if [[ ! -x .venv/bin/gunicorn ]]; then
  echo "Missing .venv/bin/gunicorn. Create the virtual environment and run pip install -r requirements.txt." >&2
  exit 1
fi

# Quotes in .env preserve special characters in password hashes such as $.
set -a
source ./.env
set +a

exec .venv/bin/gunicorn \
  --workers 1 \
  --worker-class gthread \
  --threads "${FILESERVER_THREADS:-4}" \
  --timeout "${FILESERVER_TIMEOUT:-0}" \
  --bind "${FILESERVER_BIND:-0.0.0.0:8888}" \
  --access-logfile - \
  --error-logfile - \
  server:app
