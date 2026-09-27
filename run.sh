#!/usr/bin/env sh
# Secure Repo launcher for macOS and Linux.
# First run: creates a private virtual environment next to this script and installs Secure Repo.
# Every argument is forwarded, e.g.:  ./run.sh scan https://github.com/owner/repo.git
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[x] Python 3.9+ is required (set PYTHON=/path/to/python3 to choose one)." >&2
  exit 1
fi

if [ ! -x "$DIR/.venv/bin/python" ]; then
  echo "[*] First run: creating virtual environment in $DIR/.venv"
  "$PYTHON_BIN" -m venv "$DIR/.venv"
  "$DIR/.venv/bin/python" -m pip install --quiet --upgrade pip
  "$DIR/.venv/bin/python" -m pip install --quiet -e "$DIR"
  echo "[+] Secure Repo installed."
fi

exec "$DIR/.venv/bin/python" -m secure_repo "$@"
