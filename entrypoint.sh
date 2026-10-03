#!/bin/bash
# vps container entrypoint.
# The admin API intentionally binds to loopback only (see serve() in admin-api.py),
# so we run it on 127.0.0.1:8081 and forward $PORT -> 127.0.0.1:8081 with a
# stdlib TCP proxy. This keeps the loopback security model intact on Cloud Run.
set -euo pipefail

PORT="${PORT:-8080}"

echo "[1] Starting VPN admin API on 127.0.0.1:8081 ..."
python3 /app/admin-api.py --host 127.0.0.1 --port 8081 &
API_PID=$!
sleep 1
if ! kill -0 "$API_PID" 2>/dev/null; then
  echo "[ERROR] admin-api.py failed to start" >&2
  exit 1
fi

echo "[2] Forwarding 0.0.0.0:${PORT} -> 127.0.0.1:8081 ..."
exec python3 /app/port-forward.py --listen-port "$PORT" --target-host 127.0.0.1 --target-port 8081
