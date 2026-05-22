#!/bin/bash
################################################################################
# CMP Drop-and-Poll demo
#
# Simulates an EE that:
#   1. Sends an IR (Initial Request) without reading the response — as if the
#      connection dropped before openssl could parse IP and follow up with
#      certConf. The server still completes issuance (context.WithoutCancel)
#      and persists an ISSUED transaction row.
#   2. Reconnects later with the same transactionID via a pollReq and
#      retrieves the cert the server already issued (RFC 4210 §5.3.22 /
#      RFC 9483 §4.4).
#   3. When the DMS is configured for *explicit* confirmation
#      (accept_implicit=false), sends a certConf so the transaction reaches
#      CONFIRMED state. Without certConf the CMP confirmation monitor would
#      eventually revoke the cert at the timeout deadline.
#
# Why we don't drive the IR with openssl directly
# -----------------------------------------------
# openssl's `cmp -cmd ir` always follows IP/CP with a certConf (unless you
# pass -implicit_confirm AND the server agrees). On fast local dev hardware
# the whole IR → IP → certConf → pkiConf round-trip finishes in <50 ms, so
# any `timeout` we use to "kill" the connection lands too late: the row is
# already CONFIRMED by the time we try pollReq, and the controller (rightly)
# returns "unknown transaction state".
#
# We sidestep this by building the IR DER with openssl pointing at a closed
# port — `-reqout` writes the request to disk before the TCP attempt — and
# then transmitting that DER with curl. curl never sends a certConf, so the
# server's row stays ISSUED, ready for the pollReq + certConf demo.
#
# Prerequisites
# -------------
#   - Lamassu monolithic dev server on localhost:8080
#   - A DMS with auth_mode=CLIENT_CERTIFICATE (the sample data creates
#     "sample-cmp-dms"); accept_implicit may be true OR false.
#   - python3 with stdlib only — used to build the pollReq + certConf messages.
#   - openssl 3.x, curl, jq
#
# Usage:
#   ./scripts/cmp-drop-and-poll.sh [DMS_ID [SERVER]]
################################################################################
set -euo pipefail

DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-drop-poll}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-drop-$(date +%s)"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
POLLREQ_CLIENT="${SCRIPT_DIR}/cmp_pollreq.py"
CERTCONF_CLIENT="${SCRIPT_DIR}/cmp_certconf.py"

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
echo " CMP Drop-and-Poll Demo"
echo "========================================================================"
echo "  DMS         : ${DMS_ID}"
echo "  Server      : ${SERVER}${CMP_PATH}"
echo "  Device CN   : ${DEVICE_CN}"
echo "  Workdir     : ${WORKDIR}"
echo ""

# ── Step 1: DMS config — decide signing + confirmation policy ────────────────
echo "[1/8] Reading DMS configuration..."
DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "cannot fetch DMS ${DMS_ID} at ${SERVER}"

PROT_SERIAL=$(echo "${DMS_JSON}"     | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.protection_certificate // empty')
ENFORCE_PROT=$(echo "${DMS_JSON}"    | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enforce_request_protection // false')
ENROLLMENT_CA=$(echo "${DMS_JSON}"   | jq -r '.settings.enrollment_settings.enrollment_ca // empty')
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
info "enforce_request_protection : ${ENFORCE_PROT}"
info "accept_implicit            : ${ACCEPT_IMPLICIT}"
info "enrollment_ca              : ${ENROLLMENT_CA:-<empty>}"
info "protection_certificate     : ${PROT_SERIAL:-<empty>}"

# ── Step 2: bootstrap credentials + device key ───────────────────────────────
echo ""
echo "[2/8] Provisioning bootstrap CA + signer (registered as ValidationCA)..."
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"
cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" || fail "bootstrap setup failed"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORKDIR}/device.key" 2>/dev/null
ok "bootstrap CA ${BOOTSTRAP_CA_ID} + signer + device keys ready"

# ── Step 3: build the IR DER without sending it ─────────────────────────────
#
# openssl is pointed at 127.0.0.1:1 (closed), so the eventual TCP connect()
# will fail — but `-reqout` writes the constructed IR DER to disk before that
# attempt. The non-zero exit is expected and ignored.
echo ""
echo "[3/8] Building IR DER (openssl points at a closed port — no transmission yet)..."
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

if [ ! -s "${WORKDIR}/ir-request.der" ]; then
    fail "openssl did not write the IR DER — check ${WORKDIR}/ir.stderr"
fi

TX_HEX=$(python3 -c "
import sys
with open('${WORKDIR}/ir-request.der','rb') as f: d=f.read()
i=d.find(bytes([0xa4,0x12,0x04,0x10]))
sys.exit(1) if i<0 else print(d[i+4:i+20].hex())")
ok "IR built — transactionID ${TX_HEX} ($(wc -c < "${WORKDIR}/ir-request.der") bytes)"

# ── Step 4: send the IR via curl — server processes it, we ignore the reply ─
#
# This is the "drop" simulation: the server completes LWCEnroll and writes the
# ISSUED row. curl reads the IP response into a file we never use; nothing
# sends certConf back so the row stays in ISSUED. From the server's POV this
# is indistinguishable from an EE that received the bytes and then crashed.
echo ""
echo "[4/8] Sending IR via curl, discarding response (simulated disconnect)..."
HTTP_CODE=$(curl -sS -o "${WORKDIR}/ir-response.der" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/pkixcmp" \
    --data-binary "@${WORKDIR}/ir-request.der" \
    --max-time 10 \
    "${SERVER}${CMP_PATH}" || echo "000")
info "curl HTTP status: ${HTTP_CODE} ($(wc -c < "${WORKDIR}/ir-response.der") bytes received and ignored)"
[ "${HTTP_CODE}" = "200" ] || fail "server did not accept the IR (status ${HTTP_CODE})"
ok "IR delivered; server has issued the cert and stored an ISSUED row"

# ── Step 5: confirm state via the DMS management API ────────────────────────
echo ""
echo "[5/8] Verifying transaction state via /dms/{id}/cmp/transactions..."

fetch_state() {
    local filter="filter=transaction_id%5Bequal%5D${1}"
    curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?${filter}" \
        | jq -r '.list[0].state // empty'
}

# Give the server a moment to flush the row (the IR returns the cert inline
# after Insert returns, so this is mostly belt-and-braces).
sleep 1
STATE=$(fetch_state "${TX_HEX}")
case "${STATE}" in
    ISSUED)
        ok "state=ISSUED — ready for pollReq" ;;
    "")
        fail "no transaction row found for ${TX_HEX} (filter may not be supported by the API)" ;;
    *)
        fail "unexpected state '${STATE}' — expected ISSUED" ;;
esac

# ── Step 6: pollReq to retrieve the cert ─────────────────────────────────────
echo ""
echo "[6/8] Sending pollReq with the captured transactionID..."

POLL_FLAGS=()
if [ "${ENFORCE_PROT}" = "true" ]; then
    note "DMS enforces request protection — signing the pollReq"
    POLL_FLAGS+=(--signer-cert "${WORKDIR}/signer.crt" --signer-key "${WORKDIR}/signer.key")
else
    note "DMS does NOT enforce request protection — unsigned pollReq"
fi

python3 "${POLLREQ_CLIENT}" \
    --server "${SERVER}" \
    --path "${CMP_PATH}" \
    --tx-id "${TX_HEX}" \
    --out "${WORKDIR}/pollrep.der" \
    "${POLL_FLAGS[@]}" \
    | sed 's/^/  /' \
    || fail "pollReq failed — see ${WORKDIR}/pollrep.der"

if [ ! -s "${WORKDIR}/pollrep.der" ]; then
    fail "pollReq returned no body"
fi
ok "pollRep received — cert delivered inline"

# ── Step 7: certConf when explicit confirmation is required ─────────────────
#
# RFC 4210 §5.2.8: when the EE has not requested implicit confirmation (or
# the server is not configured to grant it), certConf is mandatory to finalise
# the enrollment. Without it the row stays in ISSUED until the timeout and
# the CMP confirmation monitor revokes the cert.
echo ""
if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    echo "[7/8] DMS uses implicit confirmation — server already CONFIRMED the row on pollReq delivery. Skipping certConf."
else
    echo "[7/8] DMS requires explicit confirmation — sending certConf..."
    CC_FLAGS=()
    if [ "${ENFORCE_PROT}" = "true" ]; then
        CC_FLAGS+=(--signer-cert "${WORKDIR}/signer.crt" --signer-key "${WORKDIR}/signer.key")
    fi

    if python3 "${CERTCONF_CLIENT}" \
        --server "${SERVER}" \
        --path "${CMP_PATH}" \
        --pollrep "${WORKDIR}/pollrep.der" \
        --out "${WORKDIR}/pkiconf.der" \
        "${CC_FLAGS[@]}" \
        | sed 's/^/  /'; then
        ok "certConf accepted — server returned pkiConf"
    else
        fail "certConf was rejected by the server (see ${WORKDIR}/pkiconf.der)"
    fi
fi

# ── Step 8: verify the row reached CONFIRMED ────────────────────────────────
echo ""
echo "[8/8] Re-checking transaction state..."
sleep 1
STATE=$(fetch_state "${TX_HEX}")
case "${STATE}" in
    CONFIRMED)
        ok "state=CONFIRMED — enrollment complete" ;;
    ISSUED)
        fail "state still ISSUED — certConf was not honoured by the server (or accept_implicit is false but pollReq didn't trigger confirmation)" ;;
    "")
        fail "transaction row vanished — was DeleteExpired racing?" ;;
    *)
        fail "unexpected final state '${STATE}'" ;;
esac

echo ""
echo "========================================================================"
echo -e "${GREEN} CMP DROP-AND-POLL SUCCEEDED${RESET}"
echo "========================================================================"
echo "  - IR built by openssl, transmitted by curl (no auto-certConf)"
echo "  - server wrote cmp_transactions row in state ISSUED"
echo "  - pollReq with the same txID returned the stored cert"
if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    echo "  - implicit confirmation: row reached CONFIRMED on pollReq delivery"
else
    echo "  - certConf accepted: row reached CONFIRMED"
fi
echo ""
echo "  Files preserved in: ${WORKDIR}"
echo "    ir-request.der      – the IR built by openssl (sent by curl)"
echo "    ir-response.der     – the IP response curl received and ignored"
echo "    pollrep.der         – the pollReq response (IP/CP body, contains cert)"
if [ "${ACCEPT_IMPLICIT}" != "true" ]; then
    echo "    pkiconf.der         – the pkiConf response acknowledging certConf"
fi
echo "    signer.crt/.key     – bootstrap credential reused across IR/pollReq/certConf"
echo ""
echo "  Inspect the issued cert:"
echo "    openssl asn1parse -inform DER -in ${WORKDIR}/pollrep.der | less"
echo "========================================================================"
