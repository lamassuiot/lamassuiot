#!/bin/bash
################################################################################
# CMP IR — implicit confirmation (no certConf needed)
#
# Sends one IR carrying id-it-implicitConfirm in generalInfo. The DMS MUST be
# in implicit-confirm mode (accept_implicit=true); when both sides agree the
# server omits the certConf step entirely. We capture the IP, do NOT send
# certConf, and verify the transaction row is already in CONFIRMED state on
# the server — that's the correct outcome per RFC 4210 §5.2.8.
#
# How "implicit" is signalled to the server:
#   `openssl cmp -implicit_confirm` adds the id-it-implicitConfirm OID to the
#   request's generalInfo. The server replies with the OID echoed in the
#   response generalInfo when AcceptImplicit=true on the DMS.
#
# How we avoid the auto-certConf:
#   `openssl cmp -cmd ir` with -implicit_confirm and a cooperating server
#   would not send certConf — but we use the closed-port trick anyway so the
#   client never runs against the real server. curl POSTs the DER, the server
#   processes it, returns IP, and the row is born CONFIRMED.
#
# Expected server behaviour:
#   - HTTP 200, IP response with id-it-implicitConfirm in generalInfo
#   - DB row state = CONFIRMED, confirmed_at set
#   - confirmation monitor never touches this row (CONFIRMED is terminal)
#
# Usage:
#   ./scripts/cmp-ir-implicit.sh [DMS_ID [SERVER]]
################################################################################
set -euo pipefail

DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-ir-implicit}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-implicit-$(date +%s)"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [ -t 1 ]; then
    GREEN="\033[0;32m"; RED="\033[0;31m"; RESET="\033[0m"
else
    GREEN=""; RED=""; RESET=""
fi
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "  $*"; }
fail() { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

echo "=== CMP IR (implicit confirm) → DMS ${DMS_ID} @ ${SERVER} ==="

# Sanity-check: implicit confirm is required for this scenario to mean
# anything. accept_implicit=false makes the server demand a certConf.
DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "cannot fetch DMS ${DMS_ID}"
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
[ "${ACCEPT_IMPLICIT}" = "true" ] \
    || fail "DMS has accept_implicit=false — server would expect certConf. PATCH the DMS to accept_implicit=true and retry."

# Provision a signer the DMS trusts + a fresh device key.
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"
cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" >/dev/null || fail "bootstrap setup failed"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORKDIR}/device.key" 2>/dev/null

# Build the IR DER. -implicit_confirm adds id-it-implicitConfirm to generalInfo.
# Pointing openssl at a closed port makes it write the DER then exit before
# any response handling (so even in normal operation it cannot fire certConf).
set +e
openssl cmp \
    -cmd ir \
    -server http://127.0.0.1:1 -path /nowhere \
    -cert "${WORKDIR}/signer.crt" -key "${WORKDIR}/signer.key" \
    -extracerts "${WORKDIR}/signer.crt" \
    -newkey "${WORKDIR}/device.key" -subject "/CN=${DEVICE_CN}" \
    -implicit_confirm \
    -reqout "${WORKDIR}/ir-request.der" \
    -certout "${WORKDIR}/discard.crt" \
    -msg_timeout 1 \
    >/dev/null 2>"${WORKDIR}/ir.stderr"
set -e
[ -s "${WORKDIR}/ir-request.der" ] || { cat "${WORKDIR}/ir.stderr" >&2; fail "openssl did not write IR DER"; }

# Extract the transactionID (header field [4] OCTET STRING, 16 bytes).
TX_HEX=$(python3 -c "
import sys
with open('${WORKDIR}/ir-request.der','rb') as f: d=f.read()
i=d.find(bytes([0xa4,0x12,0x04,0x10]))
sys.exit(1) if i<0 else print(d[i+4:i+20].hex())")

# Send the IR and capture the IP.
HTTP_CODE=$(curl -sS -o "${WORKDIR}/ip-response.der" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/pkixcmp" \
    --data-binary "@${WORKDIR}/ir-request.der" \
    --max-time 10 \
    "${SERVER}${CMP_PATH}" || echo "000")
[ "${HTTP_CODE}" = "200" ] || fail "server rejected IR (HTTP ${HTTP_CODE})"

ok "IR delivered, IP captured — no certConf sent (implicit-confirm path)"
info "transactionID    : ${TX_HEX}"
info "device CN        : ${DEVICE_CN}"
info "IP response size : $(wc -c < "${WORKDIR}/ip-response.der") bytes"

# Verify the server granted implicit confirmation: the IP must echo the
# id-it-implicitConfirm OID (1.3.6.1.5.5.7.4.13) in its generalInfo. The OID
# encodes to DER as: 06 08 2B 06 01 05 05 07 04 0D
if python3 -c "
import sys
with open('${WORKDIR}/ip-response.der','rb') as f: d=f.read()
needle=bytes([0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x04,0x0D])
sys.exit(0 if needle in d else 1)"; then
    ok "IP carries id-it-implicitConfirm — server granted implicit confirmation"
else
    fail "IP does NOT carry id-it-implicitConfirm — server demanded explicit certConf (check accept_implicit on DMS, restart backend if needed)"
fi

# Verify the transaction row is CONFIRMED (terminal). Without the backend fix
# it would be ISSUED here and the monitor would revoke ~5min later.
sleep 1
STATE=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?filter=transaction_id%5Bequal%5D${TX_HEX}" \
    | jq -r '.list[0].state // empty')
case "${STATE}" in
    CONFIRMED)
        ok "transaction state = CONFIRMED — implicit confirmation persisted" ;;
    ISSUED)
        fail "state=ISSUED — backend did NOT promote the row to CONFIRMED. Restart the backend after the cmp_enrollment.go / cmptxstore.go fixes and retry." ;;
    "")
        fail "no transaction row found for ${TX_HEX}" ;;
    *)
        fail "unexpected state '${STATE}' — expected CONFIRMED" ;;
esac

echo
echo "Inspect via:"
echo "  curl -s '${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?filter=transaction_id%5Bequal%5D${TX_HEX}' | jq '.list[0]'"
