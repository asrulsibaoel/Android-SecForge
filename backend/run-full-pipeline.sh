#!/usr/bin/env bash
# Launch the AndroidSecForge backend with the FULL analysis pipeline enabled
# (jadx + Ghidra deep). All machine-specific values come from a .env file — this
# script hardcodes NO paths. Copy .env.example to .env and set your tool paths.
#
#   cp .env.example .env      # then edit ASF_JADX_PATH / ASF_GHIDRA_PATH
#   backend/run-full-pipeline.sh
#
# Config precedence: real environment > .env file > the defaults below.
# Override the env file location with:  ASF_ENV_FILE=/path/to/.env  or  arg $1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- load .env (KEY=value lines; shell-compatible) --------------------------
ENV_FILE="${ASF_ENV_FILE:-${1:-$REPO_ROOT/.env}}"
if [ -f "$ENV_FILE" ]; then
  echo "[run-full-pipeline] loading config from $ENV_FILE"
  set -a; . "$ENV_FILE"; set +a
else
  echo "[run-full-pipeline] no env file at $ENV_FILE — copy .env.example to .env and set your tool paths"
fi

# --- full-pipeline defaults (only applied if .env / env didn't set them) ----
# Tool PATHS intentionally have NO default: they must come from your .env or
# environment, never be baked into this committed script.
export ASF_GHIDRA_DEEP_ENABLED="${ASF_GHIDRA_DEEP_ENABLED:-true}"   # deep native call-chain
export ASF_GHIDRA_ENABLED="${ASF_GHIDRA_ENABLED:-false}"           # legacy per-lib stage (off)
: "${ASF_DATABASE_URL:=sqlite:///$REPO_ROOT/androidsecforge.db}"; export ASF_DATABASE_URL

# --- honest warnings if the optional analyzers aren't configured ------------
[ -n "${ASF_JADX_PATH:-}" ] || \
  echo "[run-full-pipeline] warn: ASF_JADX_PATH unset -> jadx (Java decompilation) will be UNAVAILABLE"
[ -n "${ASF_GHIDRA_PATH:-}${GHIDRA_INSTALL_DIR:-}" ] || \
  echo "[run-full-pipeline] warn: ASF_GHIDRA_PATH / GHIDRA_INSTALL_DIR unset -> Ghidra will be UNAVAILABLE"

HOST="${ASF_HOST:-127.0.0.1}"
PORT="${ASF_PORT:-8000}"
PYTHON="${ASF_PYTHON:-python3}"

cd "$SCRIPT_DIR"
echo "[run-full-pipeline] serving on http://$HOST:$PORT  (db=$ASF_DATABASE_URL)"
exec "$PYTHON" -m uvicorn app.main:app --host "$HOST" --port "$PORT" --log-level info
