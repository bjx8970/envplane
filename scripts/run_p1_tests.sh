#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/tmp/p1-venv"
PY="$VENV/bin/python"
CONTAINER_ID=""

if ! command -v podman >/dev/null 2>&1; then
  printf '%s\n' 'Local Podman is required for disposable PostgreSQL 17 tests.' >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3 with venv support is required.' >&2
  exit 2
fi

mkdir -p "$ROOT/tmp/pip-cache"
export PIP_CACHE_DIR="$ROOT/tmp/pip-cache"
if [ ! -x "$PY" ]; then
  python3 -m venv "$VENV"
fi
# Install exactly the minimal control-plane dependencies, not legacy requirements.
"$PY" -m pip install --disable-pip-version-check \
  'sqlalchemy==2.0.49' 'pg8000==1.31.5' 'alembic==1.17.2'

TOKEN="$("$PY" -c 'import secrets; print(secrets.token_hex(12))')"
CONTAINER="k8s-lab-p1-pg-$TOKEN"
DATABASE="control_plane_test_p1_$TOKEN"
PASSWORD="$("$PY" -c 'import secrets; print(secrets.token_hex(24))')"

cleanup() {
  # Only a successfully created container ID belongs to this invocation.
  if [ -n "$CONTAINER_ID" ]; then
    podman --remote=false rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# No persistent volume, no remote Podman connection, and no public port binding.
CONTAINER_ID="$(podman --remote=false run -d --rm --name "$CONTAINER" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD="$PASSWORD" \
  -e POSTGRES_DB="$DATABASE" \
  -p 127.0.0.1::5432 \
  docker.io/library/postgres:17-alpine)"

ready=0
for ((attempt = 0; attempt < 120; attempt++)); do
  if podman --remote=false exec "$CONTAINER_ID" \
    pg_isready -U postgres -d "$DATABASE" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
if [ "$ready" -ne 1 ]; then
  printf '%s\n' 'Disposable PostgreSQL 17 did not become ready.' >&2
  exit 2
fi

BINDING="$(podman --remote=false port "$CONTAINER_ID" 5432/tcp)"
PORT="${BINDING##*:}"
if [[ "$BINDING" != 127.0.0.1:* || ! "$PORT" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'Disposable PostgreSQL must have one loopback port binding.' >&2
  exit 2
fi
export CONTROL_PLANE_TEST_DATABASE_URL="postgresql+pg8000://postgres:${PASSWORD}@127.0.0.1:${PORT}/${DATABASE}"
export CONTROL_PLANE_REQUIRE_TEST_DATABASE=1
export PYTHONDONTWRITEBYTECODE=1

cd "$ROOT"
"$PY" -B "$ROOT/scripts/run_ci_tests.py" "$@"
