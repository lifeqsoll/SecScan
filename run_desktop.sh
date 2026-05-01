#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[*] Re-launching desktop app with sudo..."
  exec sudo -E bash "$0" "$@"
fi

if [[ ! -x "./.venv/bin/python" ]]; then
  echo "[-] .venv not found. Setup first:"
  echo "    python3 -m venv .venv"
  echo "    source .venv/bin/activate"
  echo "    pip install -r requirements.txt"
  exit 1
fi

./.venv/bin/python -m secscan desktop
