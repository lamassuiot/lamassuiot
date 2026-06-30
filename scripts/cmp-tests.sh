#!/bin/bash
###############################################################################
# Run the CMP compliance suite against an ALREADY-RUNNING Lamassu monolithic.
#
#   # 1. you start monolithic yourself, e.g.:
#   #      cd monolithic && go run ./cmd/development/main.go --sample-data
#   # 2. then run all the CMP tests against it:
#   scripts/cmp-tests.sh
#
# This script does NOT start, stop, or touch the monolithic server or Docker.
# It only: waits for the sample CMP DMS, prepares the suite (patch/config/venv),
# bootstraps CMP trust, and runs the tests.
#
# IMPORTANT — results are only reproducible if you run this against a FRESH
# server. The server accumulates device/cert state, so running twice against the
# same monolithic gives different numbers. Restart monolithic before each run.
#
# Env overrides:  SERVER (default http://localhost:8080)
#                 DMS    (default sample-cmp-dms)
#                 SUITE_DIR (default ~/cmp-test-suite)
###############################################################################
set -uo pipefail

LAMASSU="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="${SUITE_DIR:-$HOME/cmp-test-suite}"
SERVER="${SERVER:-http://localhost:8080}"
DMS="${DMS:-sample-cmp-dms}"
PATCH="$LAMASSU/.github/patches/cmp-test-suite/0001-lamassu-compat.patch"
say() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }

[ -d "$SUITE" ] || die "cmp-test-suite not found at $SUITE (set SUITE_DIR=...)"

# 1. The monolithic must already be running.
curl -sf "$SERVER/api/ca/v1/cas" >/dev/null 2>&1 || die \
  "No Lamassu monolithic at $SERVER. Start it first:
     cd $LAMASSU/monolithic && go run ./cmd/development/main.go --sample-data"

# 2. Wait for the CMP DMS — sample-data finishes a bit AFTER the API is up.
say "Waiting for the CMP DMS '$DMS'"
for i in $(seq 1 60); do
    curl -sf "$SERVER/api/dmsmanager/v1/dms/$DMS" >/dev/null 2>&1 && break
    [ "$i" = 60 ] && die "DMS '$DMS' never appeared — is monolithic running with --sample-data?"
    sleep 2
done

# 3. One-time suite prep (idempotent): patch, config, venv.
say "Preparing the test suite (patch, config, venv)"
cd "$SUITE"
git apply --reverse --check "$PATCH" 2>/dev/null || git apply "$PATCH" || die "could not apply compat patch"
cp "$LAMASSU/.github/patches/cmp-test-suite/lamassu.robot" config/lamassu.robot
if [ ! -x venv-cmp-tests/bin/robot ]; then
    python3 -m venv venv-cmp-tests
    venv-cmp-tests/bin/pip install -q uv && venv-cmp-tests/bin/uv pip install -e . \
        || venv-cmp-tests/bin/pip install -q -e .
fi
# shellcheck disable=SC1091
source venv-cmp-tests/bin/activate

# 4. Bootstrap CMP trust (signer cert + validation CAs + replaceable enrollment).
#    Re-run every time: a fresh server mints new CA IDs.
say "Bootstrapping CMP trust"
mkdir -p /tmp/cmp-bootstrap
bash "$LAMASSU/scripts/cmp-bootstrap-setup.sh" "$SERVER" "$DMS" /tmp/cmp-bootstrap \
    || die "CMP bootstrap failed"

# 5. Run all CMP tests.
say "Running all CMP tests"
robot --pythonpath=./ --exclude verbose-tests --exclude pqc \
      --outputdir reports --variable environment:lamassu tests/
rc=$?

python3 - reports/output.xml <<'PY'
import sys, xml.etree.ElementTree as ET
t = ET.parse(sys.argv[1]).getroot().find('.//statistics/total/stat')
print("\n================= CMP TEST RESULT =================")
print(f"  PASS={t.get('pass')}  FAIL={t.get('fail')}  SKIP={t.get('skip')}")
print(f"  report: {sys.argv[1].rsplit('/',1)[0]}/report.html")
print("==================================================")
PY
exit $rc
