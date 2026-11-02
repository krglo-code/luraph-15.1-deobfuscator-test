#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 not found"
  exit 1
fi

if [[ $# -eq 0 ]]; then
  exec python3 deob.py --auto
elif [[ $# -eq 1 ]]; then
  exec python3 deob.py "$1"
else
  exec python3 deob.py "$1" -o "$2"
fi
