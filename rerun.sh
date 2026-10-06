#!/usr/bin/env bash
# Re-run everything after the scanners, on one app folder, and keep a copy of this run's outputs.
# The scanners are NOT re-run (their output in raw/ is reused) and the free-hunt baseline is skipped.
#
#   ./rerun.sh cakeshop                      # main run: temperature 0, outputs also copied to runs/t0/
#   AGENT_TEMP=0.6 AGENT_SEED=1 ./rerun.sh cakeshop s1    # repeat run with sampling, -> runs/s1/
#
# A repeat run without AGENT_TEMP/AGENT_SEED gives the same answers as the main run (temperature 0,
# fixed seeds), so it measures nothing. See agent/llm.py.
set -e
ROOT=$(cd "$(dirname "$0")" && pwd)
APP="$1"; TAG="${2:-t0}"
[ -n "$APP" ] || { echo "usage: ./rerun.sh <app folder> [tag]"; exit 1; }
cd "$APP"
[ -f raw/bandit.json ] || { echo "no scanner output in $APP/raw/ -- run ./run.sh $APP once first"; exit 1; }
source "$ROOT/agentenv/bin/activate"
mkdir -p runs "runs/$TAG"

# replay must run the framework version the app pins, not whatever appenv has now
REQ=requirements.txt; [ -f "$REQ" ] || REQ=../requirements.txt
want=$(grep -i -E '^flask==' "$REQ" 2>/dev/null | cut -d= -f3)
have=$("$ROOT/appenv/bin/python" -c 'import importlib.metadata as m; print(m.version("flask"))')
echo "Flask in appenv: $have   pinned by the app: ${want:-none}"
if [ -n "$want" ] && [ "$want" != "$have" ] && [ -z "$ALLOW_FLASK_MISMATCH" ]; then
    echo "appenv has Flask $have but $APP pins $want. Fix appenv (see README) or set ALLOW_FLASK_MISMATCH=1."
    exit 1
fi

{
  echo "tag: $TAG"; echo "app: $APP"; date
  echo "AGENT_TEMP=${AGENT_TEMP:-unset (0)}  AGENT_SEED=${AGENT_SEED:-unset (0)}"
  echo "flask in appenv: $have (pinned: ${want:-none})"
  ollama list 2>/dev/null | grep -i qwen || echo "ollama list unavailable"
} > "runs/$TAG/run_info.txt"

step() { echo; echo "== $1"; local t=$SECONDS; shift; "$@"; echo "   ($((SECONDS - t))s)"; }

step "normalize (reuses raw/)"  python3 "$ROOT/tools/normalize.py"
step "checker"                  python3 "$ROOT/agent/verify.py"
step "merge"                    python3 "$ROOT/tools/merge_findings.py"
step "route cards"              python3 "$ROOT/agent/routecard.py"
step "rules"                    python3 "$ROOT/agent/rules.py"
step "enforce"                  python3 "$ROOT/agent/enforce.py"
step "replay"                   "$ROOT/appenv/bin/python" "$ROOT/agent/replay.py"
step "report"                   python3 "$ROOT/tools/report.py"

cp findings.json runs/verified.json runs/verified_log.json runs/merged.json runs/routecards.json \
   runs/rules.json runs/rules_log.json runs/enforce.json runs/enforce_log.json \
   runs/replay.json runs/replay_log.json runs/report.md "runs/$TAG/"

if [ -f labels/ground_truth.json ] && python3 "$ROOT/tools/score.py" --check-labels > /dev/null 2>&1; then
    {
      for f in runs/merged.json runs/enforce.json runs/replay.json \
               "runs/merged.json runs/replay.json"; do
          echo "######## $f"; python3 "$ROOT/tools/score.py" $f
          echo "######## $f --strict"; python3 "$ROOT/tools/score.py" $f --strict
      done
      python3 "$ROOT/tools/checker_eval.py" || true
      [ -f labels/expected_rules.json ] && python3 "$ROOT/tools/rules_eval.py" || true
    } > "runs/$TAG/score.txt" 2>&1
    cp runs/*_score.json "runs/$TAG/" 2>/dev/null || true
    echo; echo "== score (full output in $APP/runs/$TAG/score.txt)"
    grep -E "^=== |^found:|^precision:|^decoys:|^confirmed|^agree " "runs/$TAG/score.txt"
else
    echo; echo "no usable labels/ground_truth.json -- not scored"
fi
echo; echo "outputs copied to $APP/runs/$TAG/"
