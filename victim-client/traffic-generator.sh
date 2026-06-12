#!/usr/bin/env bash
set -euo pipefail

WEB_URL="${WEB_URL:-http://10.10.10.30:8080}"
DNS_SERVER="${DNS_SERVER:-10.10.10.53}"

echo "[victim-client] Generating HTTP and DNS lab traffic."
echo "[victim-client] WEB_URL=${WEB_URL}"
echo "[victim-client] DNS_SERVER=${DNS_SERVER}"
echo "[victim-client] Press Ctrl+C to stop."

i=0
while true; do
  i=$((i + 1))
  echo
  echo "[victim-client] iteration ${i}"

  curl -fsS "${WEB_URL}/" >/dev/null || true
  curl -fsS -X POST "${WEB_URL}/login" \
    -d "username=demo${i}&password=demo-password-${i}" >/dev/null || true

  dig @"${DNS_SERVER}" demo.local +short || true
  ping -c 1 10.10.10.30 >/dev/null 2>&1 || true

  sleep 3
done
