#!/usr/bin/env sh
# Secure Repo launcher for macOS and Linux.
# First run: creates a private virtual environment next to this script and installs Secure Repo.
# The environment is only trusted once .venv/.installed exists, and that file is written only after every install
# step succeeded; a failed first run is retried on the next launch instead of leaving a broken setup.
# Every argument is forwarded, e.g.:  ./run.sh scan https://github.com/owner/repo.git
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/.venv"
PYTHON_BIN="${PYTHON:-python3}"

if [ ! -f "$VENV/.installed" ]; then
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "[x] Python 3.11+ is required (set PYTHON=/path/to/python3 to choose one)." >&2
    exit 1
  fi
  echo "[*] First run: preparing the virtual environment in $VENV"
  [ -x "$VENV/bin/python" ] || "$PYTHON_BIN" -m venv "$VENV"
  # Dependencies come from the hashed lock file; the project itself is installed editable so updates apply live.
  if ! "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --require-hashes -r "$DIR/requirements.lock" \
     || ! "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps -e "$DIR"; then
    echo "[x] The installation failed (see the message above). Check your network connection and run this script again." >&2
    exit 1
  fi
  echo "installed" > "$VENV/.installed"
  echo "[+] Secure Repo installed."
fi

exec "$VENV/bin/python" -m secure_repo "$@"
