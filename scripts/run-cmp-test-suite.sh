#!/bin/bash
################################################################################
# Run the Siemens CMP Test Suite against a Lamassu instance.
#
# Orchestrates the full flow so you don't have to remember the steps:
#   1. (optional) start a clean SQLite-backed dev server for a pristine DB
#   2. ensure the cmp-test-suite Python venv exists with deps installed
#   3. apply the Lamassu compatibility patch if not already applied
#   4. run the CMP bootstrap (signer cert + trust CAs + replaceable enrollment)
#   5. run Robot Framework and print a pass/fail summary
#
# Usage:
#   scripts/run-cmp-test-suite.sh [options]
#
# Options:
#   --suite <path>     Run a single suite file (e.g. tests/basic.robot).
#                      Default: tests/  (the whole suite)
#   --include <tag>    Only run tests with this Robot tag (e.g. kur).
#   --test <name>      Run a single test by its exact name.
#   --fresh            Start a clean SQLite + in-memory-eventbus dev server first.
#                      Fast, fully isolated, deterministic — but WFX/event-driven
#                      CMP tests (certConf, phased workflow) are disabled, so the
#                      score is lower (~39). Good for a quick smoke check.
#   --fresh-full       Start a clean FULL-STACK dev server (Postgres + RabbitMQ +
#                      WFX in Docker). High fidelity — all CMP features work
#                      (~54) — and deterministic (fresh containers each run).
#                      Removes leftover dev containers (label
#                      group=lamassuiot-monolithic) only; never your own.
#                      Slower to start (Docker). Recommended for a real number.
#                      Without --fresh/--fresh-full, uses the server at $SERVER.
#   --per-suite-isolated
#                      Run each suite file against its own clean full stack and
#                      merge the reports (rebot). Removes cross-suite state
#                      pollution so tests that are passable in isolation actually
#                      pass (e.g. Cert Conf 0 -> 8). Slowest, but the honest
#                      "passable" count. Implies --fresh-full per suite.
#   --no-bootstrap     Skip the CMP bootstrap step (assume already provisioned).
#   -h | --help        Show this help.
#
# Environment overrides:
#   SERVER         Lamassu base URL              (default: http://localhost:8080)
#   DMS_ID         CMP DMS id                    (default: sample-cmp-dms)
#   SUITE_DIR      Path to the cmp-test-suite    (default: ~/cmp-test-suite)
#   WORKDIR        Bootstrap working dir         (default: /tmp/cmp-bootstrap)
#   LAMASSU_DIR    Path to the lamassuiot repo   (default: derived from this script)
#
# Examples:
#   scripts/run-cmp-test-suite.sh                       # full suite, existing server
#   scripts/run-cmp-test-suite.sh --fresh               # clean DB, full suite
#   scripts/run-cmp-test-suite.sh --suite tests/basic.robot
#   scripts/run-cmp-test-suite.sh --include kur
################################################################################
set -uo pipefail

# --- defaults -----------------------------------------------------------------
SERVER="${SERVER:-http://localhost:8080}"
DMS_ID="${DMS_ID:-sample-cmp-dms}"
SUITE_DIR="${SUITE_DIR:-$HOME/cmp-test-suite}"
WORKDIR="${WORKDIR:-/tmp/cmp-bootstrap}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAMASSU_DIR="${LAMASSU_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
PATCH="${LAMASSU_DIR}/.github/patches/cmp-test-suite/0001-lamassu-compat.patch"
CONFIG_SRC="${LAMASSU_DIR}/.github/patches/cmp-test-suite/lamassu.robot"  # optional seed

TARGET="tests/"
INCLUDE=""
TESTNAME=""
FRESH=0
FULL_STACK=0
DO_BOOTSTRAP=1
PER_SUITE=0

# --- args ---------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --suite)              TARGET="$2"; shift 2 ;;
        --include)            INCLUDE="$2"; shift 2 ;;
        --test)               TESTNAME="$2"; shift 2 ;;
        --fresh)              FRESH=1; shift ;;
        --fresh-full)         FRESH=1; FULL_STACK=1; shift ;;
        --per-suite-isolated) PER_SUITE=1; FRESH=1; FULL_STACK=1; shift ;;
        --no-bootstrap)       DO_BOOTSTRAP=0; shift ;;
        -h|--help)            sed -n '2,52p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                    echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }

[ -d "${SUITE_DIR}" ] || die "cmp-test-suite not found at ${SUITE_DIR} (set SUITE_DIR=...)"
[ -f "${PATCH}" ]     || die "compat patch not found at ${PATCH}"

# --- per-suite isolation ------------------------------------------------------
# Run every suite file against its OWN clean full stack, then merge the reports
# with rebot. This removes cross-suite state pollution (one suite revoking the
# shared protection cert poisons later suites), recovering tests that are
# passable in isolation (e.g. Cert Conf 0 -> 8). Slower (one stack boot per
# suite), but it yields the honest "passable" count deterministically.
if [ "${PER_SUITE}" = "1" ]; then
    log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
    die()  { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }
    PARTS_DIR="${SUITE_DIR}/reports/per-suite"
    rm -rf "${PARTS_DIR}"; mkdir -p "${PARTS_DIR}"
    suites=$(ls "${SUITE_DIR}"/tests/*.robot 2>/dev/null)
    [ -n "${suites}" ] || die "no suite files found in ${SUITE_DIR}/tests/"
    for suite in ${suites}; do
        name="$(basename "${suite}" .robot)"
        log "===== isolated suite: ${name} ====="
        # Re-invoke ourselves for a single suite against a fresh full stack.
        "${BASH_SOURCE[0]}" --fresh-full --suite "tests/${name}.robot" || true
        if [ -f "${SUITE_DIR}/reports/output.xml" ]; then
            cp "${SUITE_DIR}/reports/output.xml" "${PARTS_DIR}/${name}.xml"
        else
            warn "no output.xml for suite ${name}"
        fi
    done
    log "Merging ${PARTS_DIR}/*.xml into a combined report"
    # shellcheck disable=SC1091
    source "${SUITE_DIR}/venv-cmp-tests/bin/activate" 2>/dev/null || true
    rebot --outputdir "${SUITE_DIR}/reports" --output combined.xml \
          --report combined-report.html --log combined-log.html \
          "${PARTS_DIR}"/*.xml || true
    python3 - "${SUITE_DIR}/reports/combined.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
r = ET.parse(sys.argv[1]).getroot()
t = r.find('.//statistics/total/stat')
print("\n========= PER-SUITE-ISOLATED COMBINED RESULT =========")
print(f"  PASS={t.get('pass')}  FAIL={t.get('fail')}  SKIP={t.get('skip')}")
for s in r.findall('.//statistics/suite/stat'):
    n = s.text or ''
    if n.count('.') == 1:
        print(f"    {n[6:]:24} pass={s.get('pass'):>3} fail={s.get('fail'):>3} skip={s.get('skip'):>3}")
print("=====================================================")
PY
    exit 0
fi

PORT="${SERVER##*:}"; PORT="${PORT%%/*}"   # e.g. 8080

# Reliably stop any dev server bound to $PORT. `go run` execs a *separate*
# compiled binary (…/exe/main), so matching only 'cmd/development' leaves the
# real server orphaned on the port — which a later --fresh run then talks to,
# producing wildly different results. Kill by listener PID, then by name.
port_pid() { { ss -ltnp 2>/dev/null || true; } | grep -E "[:.]${PORT}[[:space:]]" \
             | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2; }

stop_dev_server() {
    local sig pid
    for sig in TERM TERM KILL; do
        pid="$(port_pid)"
        [ -z "${pid:-}" ] && break
        kill "-${sig}" "${pid}" 2>/dev/null || true
        pkill -"${sig}" -f "exe/main .*--sample-data" 2>/dev/null || true
        pkill -"${sig}" -f 'cmd/development/main.go' 2>/dev/null || true
        # give it a few seconds to release the port before escalating
        for _ in $(seq 1 5); do
            curl -sf "${SERVER}/api/ca/v1/cas" >/dev/null 2>&1 || return 0
            sleep 1
        done
    done
    # final check
    curl -sf "${SERVER}/api/ca/v1/cas" >/dev/null 2>&1 && return 1 || return 0
}

# Remove dev-launched Docker containers (Postgres, RabbitMQ, WFX, UI) left over
# from previous dev-server runs. They are tagged group=lamassuiot-monolithic, so
# we only ever touch dev infra — never the user's own containers. This frees the
# fixed ports WFX (9080/9081) and RabbitMQ (5672) need.
clean_dev_containers() {
    command -v docker >/dev/null 2>&1 || return 0
    local ids
    ids="$(docker ps -aq --filter 'label=group=lamassuiot-monolithic' 2>/dev/null)"
    [ -n "${ids}" ] && docker rm -f ${ids} >/dev/null 2>&1 || true
}

if [ "${FRESH}" = "1" ]; then
    log "Stopping any existing dev server on :${PORT}"
    stop_dev_server
    curl -sf "${SERVER}/api/ca/v1/cas" >/dev/null 2>&1 \
        && die "Port ${PORT} still serving after stop attempt; kill it manually and retry."

    if [ "${FULL_STACK}" = "1" ]; then
        log "Removing leftover dev containers (Postgres/RabbitMQ/WFX/UI)"
        clean_dev_containers
        log "Starting a clean FULL-STACK dev server (Postgres + RabbitMQ + WFX)"
        # Real infra so the WFX-/event-driven CMP tests (certConf, phased
        # workflow) work — this is the high-fidelity ~54 path. --disable-ui
        # skips the UI container (not needed for tests). Fresh containers each
        # run => deterministic.
        SERVER_FLAGS="--sample-data --disable-ui"
        READY_TRIES=150          # Docker pulls/boots are slow (~1-3 min)
    else
        log "Starting a clean SQLite-backed dev server (in-memory, fast)"
        # --sqlite -> in-memory DB; --inmemory-eventbus -> no RabbitMQ container.
        # No Docker, fully isolated, but WFX/event-driven CMP tests are disabled
        # (lower fidelity ~39). Good for a quick deterministic smoke.
        SERVER_FLAGS="--sample-data --sqlite --inmemory-eventbus"
        READY_TRIES=90
    fi

    ( cd "${LAMASSU_DIR}/monolithic" && \
      exec go run ./cmd/development/main.go ${SERVER_FLAGS} \
           >/tmp/lamassu-cmp-test.log 2>&1 & )
    log "Waiting for Lamassu API to be ready at ${SERVER} ..."
    for i in $(seq 1 ${READY_TRIES}); do
        curl -sf "${SERVER}/api/ca/v1/cas" >/dev/null 2>&1 && break
        [ "$i" = "${READY_TRIES}" ] && die "Lamassu did not become ready (see /tmp/lamassu-cmp-test.log)"
        sleep 2
    done
    log "Lamassu API is up."
else
    curl -sf "${SERVER}/api/ca/v1/cas" >/dev/null 2>&1 \
        || die "No Lamassu server at ${SERVER}. Start one, or pass --fresh / --fresh-full."
fi

# --- 2. venv + deps -----------------------------------------------------------
# The suite is a flat-layout project with no [build-system] in pyproject.toml,
# so it CANNOT be installed as a package: any installer that tries to build it
# (pip/uv `install .` or `-e .`, and even `uv pip install -r pyproject.toml`,
# which resolves the project itself) aborts with "Multiple top-level packages
# discovered in a flat-layout". It doesn't need to be built — Robot runs it in
# place via `robot --pythonpath=./`, so we only need its runtime dependencies
# (which include robotframework). We therefore extract [project.dependencies]
# into a plain requirements list and install just that: a flat pinned list can
# never trigger a project build, regardless of installer or its version.
cd "${SUITE_DIR}"
if [ ! -x "venv-cmp-tests/bin/robot" ]; then
    log "Creating Python venv and installing dependencies (first run only)"
    python3 -m venv venv-cmp-tests
    # shellcheck disable=SC1091
    source venv-cmp-tests/bin/activate

    REQS_FILE="$(mktemp)"
    python3 -c 'import tomllib; print("\n".join(tomllib.load(open("pyproject.toml","rb"))["project"]["dependencies"]))' \
        > "${REQS_FILE}" \
        || die "Could not extract dependencies from pyproject.toml"
    # Note: liboqs (post-quantum) is deliberately NOT installed. The suite's
    # global setup loads stateful PQ keys, which would require the liboqs binding
    # (and trigger a full liboqs source build on first import). The compat patch
    # makes that load best-effort so the classical suite runs PQ-free; PQ tests
    # are excluded at runtime via --exclude pqc.
    log "Installing $(grep -c . "${REQS_FILE}") runtime dependencies (no project build, no PQ)"
    # Prefer uv for speed; fall back to plain pip. Both are given a plain
    # requirements file, so neither attempts to build cmp-test-suite.
    if pip install --quiet uv && uv pip install -r "${REQS_FILE}"; then
        :
    else
        warn "uv install failed; falling back to pip"
        pip install --quiet -r "${REQS_FILE}" \
            || die "Failed to install cmp-test-suite dependencies"
    fi
    rm -f "${REQS_FILE}"
else
    # shellcheck disable=SC1091
    source venv-cmp-tests/bin/activate
fi
command -v robot >/dev/null 2>&1 || die "robot not found after dependency install (see output above)"

# --- 3. apply compat patch if needed -----------------------------------------
if git apply --reverse --check "${PATCH}" 2>/dev/null; then
    log "Compat patch already applied."
else
    log "Applying compat patch."
    git apply "${PATCH}" || die "Failed to apply compat patch (tree not clean?)"
fi

# config/lamassu.robot is required by --variable environment:lamassu.
if [ ! -f "config/lamassu.robot" ]; then
    if [ -f "${CONFIG_SRC}" ]; then
        log "Seeding config/lamassu.robot from ${CONFIG_SRC}"
        cp "${CONFIG_SRC}" config/lamassu.robot
    else
        die "config/lamassu.robot is missing and no seed found at ${CONFIG_SRC}"
    fi
fi

# --- 4. CMP bootstrap ---------------------------------------------------------
# The CA API comes up before sample-data finishes creating the CMP DMS, so wait
# for the DMS itself (the gate the bootstrap actually needs) to avoid a race that
# otherwise makes --fresh runs intermittently fail at bootstrap.
log "Waiting for DMS '${DMS_ID}' to be created by sample-data ..."
for i in $(seq 1 60); do
    curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}" >/dev/null 2>&1 && break
    [ "$i" = "60" ] && die "DMS '${DMS_ID}' never appeared (sample-data not run? see /tmp/lamassu-cmp-test.log)"
    sleep 2
done
log "DMS '${DMS_ID}' is present."

if [ "${DO_BOOTSTRAP}" = "1" ]; then
    log "Running CMP bootstrap (signer cert, trust CAs, replaceable enrollment)"
    mkdir -p "${WORKDIR}"
    bash "${LAMASSU_DIR}/scripts/cmp-bootstrap-setup.sh" "${SERVER}" "${DMS_ID}" "${WORKDIR}" \
        || die "CMP bootstrap failed"
fi

# --- 5. run Robot Framework ---------------------------------------------------
ROBOT_ARGS=( --pythonpath=./ --exclude verbose-tests --exclude pqc
             --outputdir=reports --variable "environment:lamassu" )
[ -n "${INCLUDE}" ]  && ROBOT_ARGS+=( --include "${INCLUDE}" )
[ -n "${TESTNAME}" ] && ROBOT_ARGS+=( --test "${TESTNAME}" )

log "Running: robot ${ROBOT_ARGS[*]} ${TARGET}"
robot "${ROBOT_ARGS[@]}" "${TARGET}"
ROBOT_RC=$?

# --- 6. summary ---------------------------------------------------------------
if [ -f reports/output.xml ]; then
    python3 - <<'PY'
import xml.etree.ElementTree as ET
r = ET.parse('reports/output.xml').getroot()
t = r.find('.//statistics/total/stat')
print("\n================ CMP TEST SUITE RESULT ================")
print(f"  PASS={t.get('pass')}  FAIL={t.get('fail')}  SKIP={t.get('skip')}")
print("  per suite:")
for s in r.findall('.//statistics/suite/stat'):
    name = s.text or ''
    if name.count('.') == 1:
        print(f"    {name[6:]:24} pass={s.get('pass'):>3} fail={s.get('fail'):>3} skip={s.get('skip'):>3}")
print("=======================================================")
print(f"  report: {__import__('os').getcwd()}/reports/report.html")
PY
fi

# Robot exits non-zero when any test fails; surface that but after the summary.
exit ${ROBOT_RC}
