#!/bin/bash
################################################################################
# CMP IR Test — Explicit Confirmation (no certConf sent)
#
# First half of the "confirmation_timeout works" test pair. Sends an Initial
# Request to a DMS configured with `accept_implicit=false`, captures the IP
# response carrying the issued cert, and leaves the transaction in ISSUED
# state on the server. Crucially it does NOT send a certConf back — that's
# what `cmp-certconf-explicit.sh` does, optionally after the server's
# confirmation timeout has elapsed so we can observe the timeout enforcement.
#
# How "no certConf" is achieved
# -----------------------------
# openssl `cmp -cmd ir` would automatically send a certConf after receiving
# IP (unless -implicit_confirm is set AND the server agrees). To suppress it
# we reuse the trick from cmp-drop-and-poll.sh: build the IR DER with openssl
# pointed at a closed port (so it writes the request and bails), then send
# the DER ourselves with curl. The server processes the IR, returns IP, the
# row enters ISSUED, and no certConf round-trip happens.
#
# Artifacts left in WORKDIR (consumed by cmp-certconf-explicit.sh)
# ----------------------------------------------------------------
#   ir-response.der    — the IP response (carries cert + senderNonce + txID)
#   signer.crt/.key    — bootstrap credential (in case the certConf is signed)
#   meta.env           — DMS_ID, SERVER, CMP_PATH, TX_HEX, timestamp
#
# Usage:
#   ./scripts/cmp-ir-explicit.sh [DMS_ID [SERVER]]
################################################################################
set -euo pipefail

DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-confirmwait}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-confirmwait-$(date +%s)"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [ -t 1 ]; then
    GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"
else
    GREEN=""; YELLOW=""; RED=""; CYAN=""; RESET=""
fi
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
note() { echo -e "${CYAN}→${RESET} $*"; }
info() { echo -e "  $*"; }
fail() { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

echo "========================================================================"
echo " CMP IR — Explicit (no certConf sent)"
echo "========================================================================"
echo "  DMS         : ${DMS_ID}"
echo "  Server      : ${SERVER}${CMP_PATH}"
echo "  Device CN   : ${DEVICE_CN}"
echo "  Workdir     : ${WORKDIR}"
echo ""

# ── Step 1: DMS config sanity check ───────────────────────────────────────────
echo "[1/5] Reading DMS configuration..."
DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "cannot fetch DMS ${DMS_ID} at ${SERVER}"

ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
CONFIRM_TIMEOUT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.confirmation_timeout // "0s"')
ENFORCE_PROT=$(echo "${DMS_JSON}"    | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enforce_request_protection // false')

info "accept_implicit            : ${ACCEPT_IMPLICIT}"
info "confirmation_timeout       : ${CONFIRM_TIMEOUT} (0s ⇒ server default 5m)"
info "enforce_request_protection : ${ENFORCE_PROT}"

if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    fail "DMS ${DMS_ID} has accept_implicit=true. This test needs explicit confirmation — the server would auto-confirm and never enforce the timeout. PATCH the DMS to accept_implicit=false and re-run."
fi

# ── Step 2: bootstrap CA + signer + device key ────────────────────────────────
echo ""
echo "[2/5] Provisioning bootstrap CA + signer (registered as ValidationCA)..."
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"
cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" || fail "bootstrap setup failed"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORKDIR}/device.key" 2>/dev/null
ok "bootstrap CA ${BOOTSTRAP_CA_ID} + signer + device keys ready"

# ── Step 3: build the IR DER (openssl points at a closed port) ───────────────
echo ""
echo "[3/5] Building IR DER (no auto-certConf — openssl never gets the IP)..."
set +e
openssl cmp \
    -cmd ir \
    -server http://127.0.0.1:1 -path /nowhere \
    -cert "${WORKDIR}/signer.crt" -key "${WORKDIR}/signer.key" \
    -extracerts "${WORKDIR}/signer.crt" \
    -newkey "${WORKDIR}/device.key" -subject "/CN=${DEVICE_CN}" \
    -reqout "${WORKDIR}/ir-request.der" \
    -certout "${WORKDIR}/discard.crt" \
    -msg_timeout 1 \
    >"${WORKDIR}/ir.stdout" 2>"${WORKDIR}/ir.stderr"
set -e

[ -s "${WORKDIR}/ir-request.der" ] \
    || fail "openssl did not write IR DER — check ${WORKDIR}/ir.stderr"

TX_HEX=$(python3 -c "
import sys
with open('${WORKDIR}/ir-request.der','rb') as f: d=f.read()
i=d.find(bytes([0xa4,0x12,0x04,0x10]))
sys.exit(1) if i<0 else print(d[i+4:i+20].hex())")
ok "IR built — transactionID ${TX_HEX} ($(wc -c < "${WORKDIR}/ir-request.der") bytes)"

# ── Step 4: send the IR via curl, KEEP the IP response ───────────────────────
echo ""
echo "[4/5] Sending IR via curl, capturing IP response (no certConf will follow)..."
HTTP_CODE=$(curl -sS -o "${WORKDIR}/ir-response.der" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/pkixcmp" \
    --data-binary "@${WORKDIR}/ir-request.der" \
    --max-time 10 \
    "${SERVER}${CMP_PATH}" || echo "000")
info "curl HTTP status : ${HTTP_CODE}"
info "IP response size : $(wc -c < "${WORKDIR}/ir-response.der") bytes"
[ "${HTTP_CODE}" = "200" ] || fail "server did not accept the IR (status ${HTTP_CODE})"
ok "IR delivered; IP response saved to ${WORKDIR}/ir-response.der"

# ── Step 5: verify the row is in ISSUED state, awaiting certConf ─────────────
echo ""
echo "[5/5] Verifying transaction state via /dms/{id}/cmp/transactions..."
fetch_state() {
    local filter="filter=transaction_id%5Bequal%5D${1}"
    curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?${filter}" \
        | jq -r '.list[0].state // empty'
}
sleep 1
STATE=$(fetch_state "${TX_HEX}")
case "${STATE}" in
    ISSUED)
        ok "state=ISSUED — row is now awaiting certConf (confirmation_timeout ticking)" ;;
    "")
        fail "no transaction row found for ${TX_HEX}" ;;
    *)
        fail "unexpected state '${STATE}' — expected ISSUED" ;;
esac

# Persist context for the certConf step.
ISSUED_AT_EPOCH=$(date +%s)
ISSUED_AT_ISO=$(date -Iseconds)
cat > "${WORKDIR}/meta.env" <<EOF
# Generated by cmp-ir-explicit.sh on ${ISSUED_AT_ISO}
DMS_ID=${DMS_ID}
SERVER=${SERVER}
CMP_PATH=${CMP_PATH}
TX_HEX=${TX_HEX}
DEVICE_CN=${DEVICE_CN}
ENFORCE_PROT=${ENFORCE_PROT}
CONFIRM_TIMEOUT=${CONFIRM_TIMEOUT}
ISSUED_AT_EPOCH=${ISSUED_AT_EPOCH}
ISSUED_AT_ISO=${ISSUED_AT_ISO}
EOF
ok "context saved to ${WORKDIR}/meta.env (for cmp-certconf-explicit.sh)"

echo ""
echo "========================================================================"
echo -e "${GREEN} IR DELIVERED — TRANSACTION IN ISSUED STATE${RESET}"
echo "========================================================================"
echo "  transactionID        : ${TX_HEX}"
echo "  state                : ISSUED (awaiting certConf)"
echo "  confirmation_timeout : ${CONFIRM_TIMEOUT} (0s ⇒ server default 5m)"
echo "  issued at            : ${ISSUED_AT_ISO}"
echo ""
echo "  Next steps to verify the timeout:"
echo "    1) wait longer than the server's confirmation_timeout"
echo "    2) run: ./scripts/cmp-certconf-explicit.sh"
echo "       — expect the server to reject the certConf and the transaction"
echo "         to be in TIMEOUT/REVOKED (cert already revoked by monitor)"
echo ""
echo "  To confirm BEFORE the timeout (sanity check), run the certConf script"
echo "  immediately — the row should transition to CONFIRMED."
echo "========================================================================"
