#!/bin/bash
################################################################################
# CMP certConf — companion to cmp-ir-explicit.sh
#
# Reads the IP response and signer credentials left in WORKDIR by
# cmp-ir-explicit.sh and sends a certConf for the same transactionID.
#
# Outcomes (the point of the test):
#   - Sent BEFORE confirmation_timeout elapses: server returns pkiConf and
#     transitions the row to CONFIRMED.
#   - Sent AFTER  confirmation_timeout elapses: server should reject the
#     certConf (transaction state TIMEOUT) and the CMP confirmation monitor
#     should have already revoked the cert.
#
# Usage:
#   ./scripts/cmp-certconf-explicit.sh
#
# Override the workdir (must match the one used by cmp-ir-explicit.sh):
#   WORKDIR=/tmp/cmp-confirmwait ./scripts/cmp-certconf-explicit.sh
################################################################################
set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/cmp-confirmwait}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CERTCONF_CLIENT="${SCRIPT_DIR}/cmp_certconf.py"

[ -f "${WORKDIR}/meta.env" ] \
    || { echo "no meta.env in ${WORKDIR} — run cmp-ir-explicit.sh first" >&2; exit 1; }
# shellcheck disable=SC1091
. "${WORKDIR}/meta.env"

[ -s "${WORKDIR}/ir-response.der" ] \
    || { echo "missing ${WORKDIR}/ir-response.der" >&2; exit 1; }

if [ -t 1 ]; then
    GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"
else
    GREEN=""; YELLOW=""; RED=""; CYAN=""; RESET=""
fi
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
note() { echo -e "${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}!${RESET} $*"; }
info() { echo -e "  $*"; }
fail() { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

ELAPSED=$(( $(date +%s) - ISSUED_AT_EPOCH ))

echo "========================================================================"
echo " CMP certConf — confirmation_timeout test"
echo "========================================================================"
echo "  DMS                  : ${DMS_ID}"
echo "  Server               : ${SERVER}${CMP_PATH}"
echo "  transactionID        : ${TX_HEX}"
echo "  confirmation_timeout : ${CONFIRM_TIMEOUT} (0s ⇒ server default 5m)"
echo "  issued at            : ${ISSUED_AT_ISO}"
echo "  elapsed since IR     : ${ELAPSED}s"
echo ""

# ── Step 1: pre-flight — what does the server think the txn state is? ───────
echo "[1/3] Pre-flight: current transaction state on the server..."
fetch_state() {
    local filter="filter=transaction_id%5Bequal%5D${1}"
    curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?${filter}" \
        | jq -r '.list[0].state // empty'
}
PRE_STATE=$(fetch_state "${TX_HEX}")
info "state before certConf : ${PRE_STATE:-<row not found>}"

# ── Step 2: send the certConf ────────────────────────────────────────────────
echo ""
echo "[2/3] Sending certConf..."
CC_FLAGS=()
if [ "${ENFORCE_PROT}" = "true" ]; then
    note "DMS enforces request protection — signing the certConf"
    CC_FLAGS+=(--signer-cert "${WORKDIR}/signer.crt" --signer-key "${WORKDIR}/signer.key")
else
    note "DMS does NOT enforce request protection — unsigned certConf"
fi

set +e
python3 "${CERTCONF_CLIENT}" \
    --server "${SERVER}" \
    --path "${CMP_PATH}" \
    --pollrep "${WORKDIR}/ir-response.der" \
    --out "${WORKDIR}/pkiconf.der" \
    "${CC_FLAGS[@]}" \
    | sed 's/^/  /'
CC_EXIT=$?
set -e
info "cmp_certconf.py exit code : ${CC_EXIT}"

# ── Step 3: post-flight — what is the state now? ─────────────────────────────
echo ""
echo "[3/3] Post-flight: transaction state after certConf attempt..."
sleep 1
POST_STATE=$(fetch_state "${TX_HEX}")
info "state after certConf  : ${POST_STATE:-<row not found>}"

# Decode any UTF8STRING error message embedded in the response (CMP errorMsg).
ERR_MSG=$(openssl asn1parse -inform DER -in "${WORKDIR}/pkiconf.der" 2>/dev/null \
    | awk -F: '/UTF8STRING/{print $NF}' | head -1)
[ -n "${ERR_MSG}" ] && info "server errorMsg       : ${ERR_MSG}"

# Resolve the confirmation_timeout to seconds for the post-flight verdict.
# Server default when "0s" is configured = 5 minutes (cmpTxTTL).
to_seconds() {
    local v="$1"
    case "${v}" in
        ""|0s|0) echo 300 ;;
        *s) echo "${v%s}" ;;
        *m) echo $(( ${v%m} * 60 )) ;;
        *h) echo $(( ${v%h} * 3600 )) ;;
        *)  echo 0 ;;
    esac
}
TIMEOUT_S=$(to_seconds "${CONFIRM_TIMEOUT}")
PAST_TIMEOUT=0
[ "${ELAPSED}" -gt "${TIMEOUT_S}" ] && PAST_TIMEOUT=1

echo ""
echo "========================================================================"
case "${POST_STATE}" in
    CONFIRMED)
        if [ ${CC_EXIT} -eq 0 ]; then
            ok "certConf accepted — row is CONFIRMED (within confirmation_timeout)"
        else
            warn "row is CONFIRMED but certConf client exited non-zero — inspect ${WORKDIR}/pkiconf.der"
        fi
        ;;
    TIMEOUT|REVOKED)
        ok "row is ${POST_STATE} — server enforced the confirmation_timeout"
        info "the CMP confirmation monitor has revoked the issued cert at the CA"
        ;;
    ISSUED)
        if [ ${PAST_TIMEOUT} -eq 1 ] && [ ${CC_EXIT} -ne 0 ]; then
            ok "confirmation_timeout enforced on the certConf handler"
            info "${ELAPSED}s elapsed > ${TIMEOUT_S}s timeout — server rejected the certConf"
            info "row still reads ISSUED because the CMPConfirmationMonitor"
            info "(default frequency 2m) hasn't swept it yet; it will become REVOKED"
            info "on the next monitor tick."
        elif [ ${PAST_TIMEOUT} -eq 1 ]; then
            warn "elapsed > timeout but the server accepted the certConf — check ${WORKDIR}/pkiconf.der"
        else
            warn "row is still ISSUED and elapsed (${ELAPSED}s) < timeout (${TIMEOUT_S}s) — did the certConf message itself fail?"
        fi
        ;;
    "")
        if [ ${PAST_TIMEOUT} -eq 1 ]; then
            ok "row purged by DeleteExpired after the timeout — server enforced the deadline"
        else
            warn "row vanished before the timeout — unexpected"
        fi
        ;;
    *)
        warn "row in unexpected state '${POST_STATE}'"
        ;;
esac
echo "========================================================================"
echo "  pkiconf.der : ${WORKDIR}/pkiconf.der ($(wc -c < "${WORKDIR}/pkiconf.der" 2>/dev/null || echo 0) bytes)"
echo "========================================================================"

exit ${CC_EXIT}
