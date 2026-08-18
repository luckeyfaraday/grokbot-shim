#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GROKBOT_APP="${GROKBOT_APP:-/opt/Grok Bot/sand}"
failed=0

check_command() {
  if command -v "$1" >/dev/null 2>&1; then
    echo "ok  $1"
  else
    echo "missing  $1"
    failed=1
  fi
}

check_file() {
  if [[ -e "$1" ]]; then
    echo "ok  ${1#"$ROOT/"}"
  else
    echo "missing  ${1#"$ROOT/"}"
    failed=1
  fi
}

check_command node
check_command npm
check_command openssl
check_command docker
check_command curl
check_command python3
check_file "$GROKBOT_APP"
check_file "$ROOT/certs/rootCA.pem"
check_file "$ROOT/certs/localhost.pem"
check_file "$ROOT/certs/localhost.key"
check_file "$ROOT/host/dist/host/host-main.cjs"
check_file "$ROOT/state/native-session-venv/bin/python"

if [[ -x "$ROOT/state/native-session-venv/bin/python" ]] && \
  "$ROOT/state/native-session-venv/bin/python" -c 'import cryptography, secretstorage' >/dev/null 2>&1; then
  echo "ok  native Grok Bot session bridge"
else
  echo "missing  native Grok Bot session bridge"
  failed=1
fi

if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
  echo "unavailable  Docker daemon"
  failed=1
else
  echo "ok  Docker daemon"
fi

if [[ "$failed" -ne 0 ]]; then
  echo "doctor found missing prerequisites; run: npm run setup" >&2
  exit 1
fi

echo "ready"
