#!/usr/bin/env bash
# Automatic Log Anomaly Detector — Git Bash launcher (Windows).
#
#   bash run.sh          # set up (first time) + run the server
#   bash run.sh test     # run the pytest suite
#
set -e

cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] Creating virtual environment (.venv)..."
  py -3.12 -m venv .venv
fi

# Git Bash activation path on Windows
source .venv/Scripts/activate

if [ "${1:-run}" = "test" ]; then
  echo "[*] Installing dev requirements..."
  pip install -q -r requirements.txt
  echo "[*] Running pytest..."
  python -m pytest -v
  exit 0
fi

echo "[*] Installing requirements..."
pip install -q -r requirements.txt

echo "[*] Starting server on http://127.0.0.1:8000 ..."
python -m uvicorn backend.main:app --reload
