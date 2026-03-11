#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment in $VENV_DIR..."
  python -m venv "$VENV_DIR"
else
  echo "Virtual environment already exists in $VENV_DIR"
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

echo "Installing dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "Setup complete."
