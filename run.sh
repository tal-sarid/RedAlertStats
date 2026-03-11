#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "Virtual environment not found. Run ./setup.sh first."
  exit 1
fi

# Support both Unix and Windows venv layouts (useful for Git Bash on Windows).
if [ -f "$VENV_DIR/bin/activate" ]; then
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
  # shellcheck disable=SC1091
  source "$VENV_DIR/Scripts/activate"
else
  echo "Could not find activation script inside $VENV_DIR"
  exit 1
fi

echo "Starting Flask app..."
exec python app.py "$@"
