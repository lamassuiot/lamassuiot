#!/bin/bash
################################################################################
# CMP Phased-Workflow Poll Demo
#
# Exercises the admin-approved ("phased") CMP enrollment workflow end to end:
#
#   1. Build + send an IR. A phased DMS does NOT issue inline — it parks the
#      request in a PENDING transaction and returns a "waiting" response
#      (RFC 9483 §4.4 / RFC 4210 §5.3.22).
#   2. Poll (pollReq) for the certificate. While the request is awaiting
#      administrator approval the server answers pollRep (body tag 26 = still
#      PENDING). Once an admin approves it, the next pollReq returns the cert
#      (IP/CP, body tag 1/3).
#   3. When the DMS requires explicit confirmation, send a certConf so the row
#      reaches CONFIRMED. With implicit confirmation the server confirms the
#      row the moment the cert is delivered, so certConf is skipped.
#
# The script does NOT approve the transaction for you — that is the operator's
# job (the whole point of the phased workflow). Approve it either from the
# dashboard (RA → CMP transactions → Approve) or with the curl one-liner the
# script prints. The poll loop simply waits for that approval to land.
#
# Polling modes:
#   POLL_MODE=auto   (default) — poll automatically every POLL_INTERVAL seconds
#   POLL_MODE=manual           — wait for the user to press Enter before each poll
#
# Prerequisites:
#   - Lamassu monolithic dev server on localhost:8080
#   - A DMS configured with lwc_rfc9483_settings.workflow = "phased"
#     (the bundled sample-cmp-dms is configured this way)
#   - python3 (stdlib only), openssl 3.x, curl, jq
#
# Usage:
#   ./scripts/cmp-phased-poll.sh [DMS_ID [SERVER]]
#   POLL_MODE=manual ./scripts/cmp-phased-poll.sh
#   POLL_INTERVAL=10 ./scripts/cmp-phased-poll.sh sample-cmp-dms http://localhost:8080
################################################################################
set -euo pipefail

# ── Parameters ───────────────────────────────────────────────────────────────
DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
POLL_MODE="${POLL_MODE:-auto}"          # auto | manual
POLL_INTERVAL="${POLL_INTERVAL:-5}"     # seconds between polls in auto mode
MAX_POLLS="${MAX_POLLS:-240}"           # safety cap (240 × 5s = 20 min)
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
MGMT_BASE="${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-phased-poll}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-phased-$(date +%s)"
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
warn() { echo -e "${YELLOW}!${RESET} $*"; }
fail() { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

echo "========================================================================"
echo " CMP Phased-Workflow Poll Demo"
echo "========================================================================"
echo "  DMS         : ${DMS_ID}"
echo "  Server      : ${SERVER}${CMP_PATH}"
echo "  Device CN   : ${DEVICE_CN}"
echo "  Poll mode   : ${POLL_MODE} (interval ${POLL_INTERVAL}s)"
echo "  Workdir     : ${WORKDIR}"
echo ""

# ── Step 1: DMS config — signing + confirmation + workflow policy ────────────
echo "[1/6] Reading DMS configuration..."
DMS_JSON=$(curl -sf "${MGMT_BASE}") || fail "cannot fetch DMS ${DMS_ID} at ${SERVER}"

AUTH_MODE=$(echo "${DMS_JSON}"       | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.auth_mode // "NO_AUTH"')
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
WORKFLOW=$(echo "${DMS_JSON}"        | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.workflow // "direct"')
# Protection is required when auth_mode demands a client certificate (signature-
# based protection). This mirrors the server logic in cmp.go: requireProtection
# is true for CLIENT_CERTIFICATE and CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK.
if [ "${AUTH_MODE}" = "CLIENT_CERTIFICATE" ] || [ "${AUTH_MODE}" = "CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK" ]; then
    ENFORCE_PROT="true"
else
    ENFORCE_PROT="false"
fi
info "workflow                   : ${WORKFLOW}"
info "auth_mode                  : ${AUTH_MODE}"
info "requires protection        : ${ENFORCE_PROT}"
info "accept_implicit            : ${ACCEPT_IMPLICIT}"
[ "${WORKFLOW}" = "phased" ] || warn "DMS workflow is '${WORKFLOW}', not 'phased' — issuance will be inline and the first poll should already return the cert."

# ── Step 2: bootstrap credentials + device key ───────────────────────────────
echo ""
echo "[2/6] Provisioning bootstrap CA + signer (registered as ValidationCA)..."
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"
cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" || fail "bootstrap setup failed"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORKDIR}/device.key" 2>/dev/null
ok "bootstrap CA ${BOOTSTRAP_CA_ID} + signer + device keys ready"

# ── Step 3: build the IR DER (openssl points at a closed port — no send) ─────
echo ""
echo "[3/6] Building IR DER..."
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
[ -s "${WORKDIR}/ir-request.der" ] || fail "openssl did not write the IR DER — see ${WORKDIR}/ir.stderr"

TX_HEX=$(python3 -c "
import sys
with open('${WORKDIR}/ir-request.der','rb') as f: d=f.read()
i=d.find(bytes([0xa4,0x12,0x04,0x10]))
sys.exit(1) if i<0 else print(d[i+4:i+20].hex())")
ok "IR built — transactionID ${TX_HEX}"

# ── Step 4: send the IR — expect a 'waiting' response, row parked PENDING ─────
echo ""
echo "[4/6] Sending IR (phased DMS returns a 'waiting' response)..."
HTTP_CODE=$(curl -sS -o "${WORKDIR}/ir-response.der" -w "%{http_code}" \
    -X POST -H "Content-Type: application/pkixcmp" \
    --data-binary "@${WORKDIR}/ir-request.der" --max-time 10 \
    "${SERVER}${CMP_PATH}" || echo "000")
[ "${HTTP_CODE}" = "200" ] || fail "server did not accept the IR (HTTP ${HTTP_CODE})"

fetch_state() {
    curl -sf "${MGMT_BASE}/cmp/transactions?filter=transaction_id%5Bequal%5D${1}" \
        | jq -r '.list[0].state // empty'
}
sleep 1
STATE=$(fetch_state "${TX_HEX}")
case "${STATE}" in
    PENDING) ok "transaction parked in PENDING — awaiting administrator approval" ;;
    ISSUED)  ok "transaction already ISSUED (direct workflow) — first poll will return the cert" ;;
    "")      fail "no transaction row found for ${TX_HEX} — was it created?" ;;
    *)       fail "unexpected state '${STATE}' after IR" ;;
esac

echo ""
note "To release this request, approve it as an administrator:"
info "  • Dashboard: RA → CMP transactions → Approve"
info "  • API:       curl -X POST ${MGMT_BASE}/cmp/transactions/${TX_HEX}/approve"
echo ""

# ── Step 5: poll until the certificate is ready ──────────────────────────────
echo "[5/6] Polling for the certificate..."
POLL_FLAGS=()
if [ "${ENFORCE_PROT}" = "true" ]; then
    POLL_FLAGS+=(--signer-cert "${WORKDIR}/signer.crt" --signer-key "${WORKDIR}/signer.key")
fi

attempt=0
while :; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -gt "${MAX_POLLS}" ]; then
        fail "gave up after ${MAX_POLLS} polls — the request was never approved"
    fi

    if [ "${POLL_MODE}" = "manual" ]; then
        read -r -p "  Press Enter to poll (#${attempt}), or 'q' to quit: " ans
        [ "${ans}" = "q" ] && fail "aborted by user after ${attempt} polls"
    fi

    POLL_OUT=$(python3 "${POLLREQ_CLIENT}" \
        --server "${SERVER}" --path "${CMP_PATH}" \
        --tx-id "${TX_HEX}" --out "${WORKDIR}/pollrep.der" \
        "${POLL_FLAGS[@]}" 2>&1) || { echo "${POLL_OUT}" | sed 's/^/    /'; fail "pollReq failed"; }
    TAG=$(echo "${POLL_OUT}" | sed -n 's/.*Body tag *: *\([0-9]\{1,\}\).*/\1/p' | head -1)

    case "${TAG}" in
        1|3)
            ok "poll #${attempt}: certificate delivered (body tag ${TAG})"
            break ;;
        26)
            note "poll #${attempt}: still PENDING (pollRep) — not yet approved"
            [ "${POLL_MODE}" = "auto" ] && sleep "${POLL_INTERVAL}" ;;
        23)
            echo "${POLL_OUT}" | sed 's/^/    /'
            fail "poll #${attempt}: server returned a CMP error (the approval may have failed)" ;;
        *)
            echo "${POLL_OUT}" | sed 's/^/    /'
            fail "poll #${attempt}: unexpected response (body tag '${TAG:-?}')" ;;
    esac
done

# ── Step 6: certConf (explicit) or done (implicit), then verify CONFIRMED ────
echo ""
if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    echo "[6/6] Implicit confirmation — server confirmed the row on cert delivery; no certConf needed."
else
    echo "[6/6] Explicit confirmation — sending certConf..."
    CC_FLAGS=()
    if [ "${ENFORCE_PROT}" = "true" ]; then
        CC_FLAGS+=(--signer-cert "${WORKDIR}/signer.crt" --signer-key "${WORKDIR}/signer.key")
    fi
    python3 "${CERTCONF_CLIENT}" \
        --server "${SERVER}" --path "${CMP_PATH}" \
        --pollrep "${WORKDIR}/pollrep.der" --out "${WORKDIR}/pkiconf.der" \
        "${CC_FLAGS[@]}" | sed 's/^/  /' \
        || fail "certConf was rejected (see ${WORKDIR}/pkiconf.der)"
    ok "certConf accepted — server returned pkiConf"
fi

sleep 1
STATE=$(fetch_state "${TX_HEX}")
[ "${STATE}" = "CONFIRMED" ] || fail "final state is '${STATE}', expected CONFIRMED"

echo ""
echo "========================================================================"
echo -e "${GREEN} CMP PHASED-WORKFLOW POLL SUCCEEDED${RESET}"
echo "========================================================================"
echo "  txID        : ${TX_HEX}"
echo "  device CN   : ${DEVICE_CN}"
echo "  final state : ${STATE}"
echo "  artifacts   : ${WORKDIR}/{ir-request,ir-response,pollrep,pkiconf}.der"
