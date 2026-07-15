#!/usr/bin/env bash
# Tear down the CyberArmor URL Trust Gate demo — stops containers and removes
# the data volumes. Leaves .env in place (delete it manually to rotate secrets).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || ENV_FILE="$ROOT_DIR/.env.example"
echo "==> Stopping stack and removing volumes"
docker compose --env-file "$ENV_FILE" -f docker-compose.yml down -v --remove-orphans
echo "==> Done. Run ./install.sh to bring it back up."
