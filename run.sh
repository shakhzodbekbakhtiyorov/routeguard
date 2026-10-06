#!/usr/bin/env bash
# Run the whole pipeline on one app folder:   ./run.sh cakeshop
# Needs agentenv/ (scanners), appenv/ (the app's own dependencies, for replay), gitleaks, and Ollama.
set -e
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$1"
mkdir -p raw runs
source "$ROOT/agentenv/bin/activate"
REQ=requirements.txt; [ -f "$REQ" ] || REQ=../requirements.txt

echo "== 1. scanners"
bandit -r . -x ./labels,./runs,./raw -f json -o raw/bandit.json -q || true
semgrep scan --config p/python --config p/flask --json -o raw/semgrep.json -q \
    --exclude labels --exclude runs --exclude raw .
pip-audit -r "$REQ" -f json -o raw/pip_audit.json || true
gitleaks dir . -f json -r raw/gitleaks.json --exit-code 0
python3 "$ROOT/tools/normalize.py"

echo "== 2. checker"
python3 "$ROOT/agent/verify.py"
python3 "$ROOT/tools/merge_findings.py"

echo "== 3. route by route"
python3 "$ROOT/agent/routecard.py"
python3 "$ROOT/agent/rules.py"
python3 "$ROOT/agent/enforce.py"
"$ROOT/appenv/bin/python" "$ROOT/agent/replay.py"

echo "== 4. human-readable report"
python3 "$ROOT/tools/report.py"            # -> runs/report.md

if [ -f labels/ground_truth.json ]; then
    echo "== 5. score"
    python3 "$ROOT/tools/score.py" runs/merged.json runs/replay.json
fi
