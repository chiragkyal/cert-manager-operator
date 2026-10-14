#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Resolve workspace: arg > env var > config.json > parent dir
if [ -n "${1:-}" ]; then
  export OPSX_WORKSPACE="$1"
elif [ -n "${OPSX_WORKSPACE:-}" ]; then
  export OPSX_WORKSPACE
elif [ -f "config.json" ]; then
  CFG_WORKSPACE="$(grep '"workspace"' config.json | sed 's/.*: *"\(.*\)".*/\1/' | sed 's/,$//')"
  if [ -n "$CFG_WORKSPACE" ] && [[ "$CFG_WORKSPACE" != *'${'* ]]; then
    export OPSX_WORKSPACE="$CFG_WORKSPACE"
  else
    export OPSX_WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
  fi
else
  export OPSX_WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

export PYTHONPATH="$OPSX_WORKSPACE${PYTHONPATH:+:$PYTHONPATH}"

echo "==> OpenSpec Observability Dashboard"
echo "    Workspace:  $OPSX_WORKSPACE"
echo "    Changes:    $OPSX_WORKSPACE/openspec/changes"
echo "    PYTHONPATH: $PYTHONPATH"
echo ""

if [ ! -d "$OPSX_WORKSPACE/openspec" ]; then
  echo "Warning: $OPSX_WORKSPACE/openspec/ not found. Dashboard may not find pipeline data."
  echo ""
fi

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  echo "==> Docker detected. Starting dashboard with Docker Compose..."
  OPSX_WORKSPACE="$OPSX_WORKSPACE" docker compose up -d --build
  echo ""
  echo "Dashboard running at http://localhost:5173"
  echo "Backend API at http://localhost:8000"
  echo ""
  echo "To stop:  cd $SCRIPT_DIR && docker compose down"
  echo "To logs:  cd $SCRIPT_DIR && docker compose logs -f"
else
  echo "==> Docker not found. Setting up locally..."
  echo ""

  if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is required. Install Python 3.10+ and try again."
    exit 1
  fi

  if ! command -v node &>/dev/null; then
    echo "Error: node is required. Install Node.js 18+ and try again."
    exit 1
  fi

  if [ ! -d ".venv" ]; then
    echo "    Creating Python virtual environment..."
    python3 -m venv .venv
  fi

  echo "    Installing Python dependencies..."
  .venv/bin/pip install -q -r requirements.txt

  echo "    Installing frontend dependencies..."
  cd web && npm install && cd ..

  BACKEND_PORT=8000
  FRONTEND_PORT=5173

  port_in_use() {
    if command -v ss &>/dev/null; then
      ss -tlnH "sport = :$1" 2>/dev/null | grep -q .
    elif command -v lsof &>/dev/null; then
      lsof -iTCP:"$1" -sTCP:LISTEN -t &>/dev/null
    else
      : # can't check, let the process fail naturally
      return 1
    fi
  }

  if port_in_use "$BACKEND_PORT"; then
    echo "Error: port $BACKEND_PORT is already in use. Stop the existing process first."
    echo "       lsof -i :$BACKEND_PORT   # find the process"
    echo "       kill \$(lsof -t -i :$BACKEND_PORT)   # kill it"
    exit 1
  fi
  if port_in_use "$FRONTEND_PORT"; then
    echo "Error: port $FRONTEND_PORT is already in use. Stop the existing process first."
    echo "       lsof -i :$FRONTEND_PORT   # find the process"
    echo "       kill \$(lsof -t -i :$FRONTEND_PORT)   # kill it"
    exit 1
  fi

  echo ""
  echo "==> Starting dashboard (backend + frontend)..."
  echo "    Backend: http://localhost:$BACKEND_PORT"
  echo "    Frontend: http://localhost:$FRONTEND_PORT"
  echo ""

  OPSX_WORKSPACE="$OPSX_WORKSPACE" PYTHONPATH="$PYTHONPATH" \
    .venv/bin/uvicorn src.main:app --reload --host 0.0.0.0 --port "$BACKEND_PORT" &
  BACKEND_PID=$!

  sleep 1
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "Error: backend failed to start. Check the output above."
    exit 1
  fi

  cd web && npm run dev &
  FRONTEND_PID=$!
  cd ..

  trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT INT TERM
  wait
fi
