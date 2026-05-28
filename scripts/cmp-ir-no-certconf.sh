#!/bin/bash
################################################################################
# CMP IR — no certConf (intentional)
#
# Minimal script: send a single IR, capture the IP, do NOT send certConf.
# The DMS MUST be in explicit-confirm mode (accept_implicit=false); otherwise
# the server auto-confirms on IP delivery and the "no certConf" property is
# meaningless.
#
# Expected server behaviour:
#   - IP returned, transaction row left in ISSUED state
#   - certConf wait clock starts (DMS confirmation_timeout, default 5m)
#   - on timeout, the CMP confirmation monitor revokes the cert
#     (cessationOfOperation) and moves the row to REVOKED
#
# How "no certConf" is achieved:
#   `openssl cmp -cmd ir` would auto-send certConf after IP. We sidestep that
#   by pointing openssl at a closed port (it writes the IR DER and bails),
#   then curl posts the DER to the real server. The client never sees IP.
#
# Usage:
#   ./scripts/cmp-ir-no-certconf.sh [DMS_ID [SERVER]]
################################################################################
set -euo pipefail

DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-ir-no-certconf}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-no-certconf-$(date +%s)"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [ -t 1 ]; then
    GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; RESET="\033[0m"
else
    GREEN=""; YELLOW=""; RED=""; RESET=""
fi
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "  $*"; }
fail() { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

echo "=== CMP IR (no certConf) → DMS ${DMS_ID} @ ${SERVER} ==="

# Sanity-check the DMS: explicit confirm is required for this scenario to mean
# anything. accept_implicit=true would make the server confirm on its own.
DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "cannot fetch DMS ${DMS_ID}"
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
CONFIRM_TIMEOUT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.confirmation_timeout // "0s"')
[ "${ACCEPT_IMPLICIT}" = "true" ] && fail "DMS has accept_implicit=true — server would auto-confirm. Set accept_implicit=false on ${DMS_ID} and retry."

# Provision a fresh signer (chain-validated by the DMS) and a device key.
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"
cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" >/dev/null || fail "bootstrap setup failed"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORKDIR}/device.key" 2>/dev/null

# Build the IR DER (openssl exits before any IP arrives → no auto-certConf).
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
    >/dev/null 2>"${WORKDIR}/ir.stderr"
set -e
[ -s "${WORKDIR}/ir-request.der" ] || { cat "${WORKDIR}/ir.stderr" >&2; fail "openssl did not write IR DER"; }

# Pull the transactionID out of the IR DER (header field [4] OCTET STRING, 16 bytes).
TX_HEX=$(python3 -c "
import sys
with open('${WORKDIR}/ir-request.der','rb') as f: d=f.read()
i=d.find(bytes([0xa4,0x12,0x04,0x10]))
sys.exit(1) if i<0 else print(d[i+4:i+20].hex())")

# Send the IR over HTTP and capture the IP DER. The server processes the
# request, returns IP, and leaves the row in ISSUED awaiting certConf.
HTTP_CODE=$(curl -sS -o "${WORKDIR}/ip-response.der" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/pkixcmp" \
    --data-binary "@${WORKDIR}/ir-request.der" \
    --max-time 10 \
    "${SERVER}${CMP_PATH}" || echo "000")
[ "${HTTP_CODE}" = "200" ] || fail "server rejected IR (HTTP ${HTTP_CODE})"

ok "IR delivered, IP captured — certConf intentionally NOT sent"
info "transactionID        : ${TX_HEX}"
info "device CN            : ${DEVICE_CN}"
info "IP response size     : $(wc -c < "${WORKDIR}/ip-response.der") bytes"
info "confirmation_timeout : ${CONFIRM_TIMEOUT} (0s ⇒ server default 5m)"
info "artifacts            : ${WORKDIR}"
echo
echo "Expected lifecycle (without your intervention):"
echo "  now              → tx state = ISSUED (awaiting certConf)"
echo "  after timeout    → CMP confirmation monitor revokes cert, tx state = REVOKED"
echo
echo "Inspect via:"
echo "  curl -s '${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?filter=transaction_id%5Bequal%5D${TX_HEX}' | jq '.list[0]'"
