#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-192.168.20.169}"
REMOTE_DIR="${2:-/opt/firewall-policy-tools}"

if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync is required" >&2
  exit 1
fi

ssh "$HOST" "mkdir -p '$REMOTE_DIR'"
rsync -az --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude 'data' \
  ./ "$HOST:$REMOTE_DIR/"

ssh "$HOST" "cd '$REMOTE_DIR' && docker compose up -d --build"

echo "Deployed to http://$HOST:8080"
