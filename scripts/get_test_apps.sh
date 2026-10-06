#!/usr/bin/env bash
# Download the third-party test app into the folder the pipeline expects:
#
#   flask-webgoat/      from https://github.com/ShiftLeftSecurity/flask-webgoat (Apache-2.0 licence)
#
# Its code is not stored in this repository. What the repository does keep for it is my own work: the
# answer key (labels/), the replay glue (app_factory.py, replay_config.json) and the saved results
# (findings.json, raw/, runs/).
#
# The app is pinned to the exact commit used for the results in this repository. The only change made to
# it: the author's "# vulnerability: ..." comments are deleted, so the model cannot read the answers in
# the code.
#
# Usage (from anywhere):  scripts/get_test_apps.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

WEBGOAT_URL=https://github.com/ShiftLeftSecurity/flask-webgoat.git
WEBGOAT_COMMIT=c481018c39e76e5758fabc27efabadc34a0d4dd6

fetch() {   # fetch <url> <dir> <commit>
    git clone --quiet "$1" "$2"
    git -C "$2" checkout --quiet "$3"
}

echo "== flask-webgoat"
fetch "$WEBGOAT_URL" "$TMP/webgoat" "$WEBGOAT_COMMIT"
mkdir -p "$ROOT/flask-webgoat"
# The app itself; the upstream README, Dockerfile and CI files are left out (flask-webgoat/README.md
# in this repository explains the folder instead).
cp "$TMP/webgoat/LICENSE" "$TMP/webgoat/requirements.txt" "$TMP/webgoat/run.py" "$ROOT/flask-webgoat/"
rm -rf "$ROOT/flask-webgoat/flask_webgoat"
cp -R "$TMP/webgoat/flask_webgoat" "$ROOT/flask-webgoat/"
# Remove the answers written in the code ("# vulnerability: SQL Injection", ...).
find "$ROOT/flask-webgoat/run.py" "$ROOT/flask-webgoat/flask_webgoat" -name '*.py' \
    -exec perl -ni -e 'print unless /# vulnerability:/' {} +

left=$(grep -rn "# vulnerability:" "$ROOT/flask-webgoat" --include='*.py' || true)
if [ -n "$left" ]; then
    echo "warning: answer comments still present:"; echo "$left"; exit 1
fi

echo
echo "Done. flask-webgoat is in flask-webgoat/."
echo "It needs its own Python environment for the replay step; see README.md, 'Test apps'."
