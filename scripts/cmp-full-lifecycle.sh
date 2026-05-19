#!/bin/bash
################################################################################
# Full CMP Lifecycle Test: IR → KUR → RR
#
# Exercises the complete CMP device lifecycle against a Lamassu DMS configured
# with:
#   - enforce_request_protection: true
#   - enforce_popo: true
#   - accept_implicit: true
#   - auth_mode: CLIENT_CERTIFICATE (accepts any client cert at chain_level 0)
#
# Flow:
#   1. Fetch the RA protection certificate from the Lamassu CA API (so the
#      client can verify server responses via -srvcert).
#   2. Generate a self-signed signer cert (bootstrap credential for IR).
#   3. IR  — Initial Registration; produces the first device certificate.
#   4. KUR — Key Update Request; uses the IR-issued cert as protection,
#            enrolls a fresh key, produces device2.crt.
#   5. RR  — Revocation Request; revokes device2.crt.
#
# Prerequisites:
#   - Lamassu monolithic dev server running on localhost:8080
#     (go run ./monolithic/cmd/development/main.go)
#   - A DMS created via the Lamassu API with the settings above
#   - The DMS's protection_certificate serial known (passed as arg or env)
#   - openssl 3.x with CMP support (openssl cmp)
#   - curl, jq
#
# Usage:
#   ./scripts/cmp-full-lifecycle.sh [DMS_ID [SERVER [PROTECTION_CERT_SERIAL]]]
#
# Examples:
#   ./scripts/cmp-full-lifecycle.sh CMP
#   ./scripts/cmp-full-lifecycle.sh CMP http://localhost:8080
#   DMS_ID=CMP SERVER=http://localhost:8080 ./scripts/cmp-full-lifecycle.sh
################################################################################
set -euo pipefail

# ── Parameters ─────────────────────────────────────────────────────────────────
DMS_ID="${1:-${DMS_ID:-CMP}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
WORKDIR=$(mktemp -d)
DEVICE_CN="cmp-device-$(date +%s)"

# Colour helpers (no-op when not a terminal)
if [ -t 1 ]; then
    GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; RESET="\033[0m"
else
    GREEN=""; YELLOW=""; RED=""; RESET=""
fi

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "  $*"; }
fail() { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

echo "========================================================================"
echo " CMP Full Lifecycle Test: IR → KUR → RR"
echo "========================================================================"
echo "  DMS ID  : ${DMS_ID}"
echo "  Server  : ${SERVER}${CMP_PATH}"
echo "  Device  : ${DEVICE_CN}"
echo "  Workdir : ${WORKDIR}"
echo ""

# ── Step 1: Fetch DMS config and protection certificate ─────────────────────────
echo "[1/5] Fetching DMS config and RA protection certificate..."

DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "Cannot reach ${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}"

PROTECTION_SERIAL=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.protection_certificate // empty')
ENFORCE_PROTECTION=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enforce_request_protection // false')
ENFORCE_POPO=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enforce_popo // false')
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
ENROLLMENT_CA=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enrollment_ca // empty')

info "enforce_request_protection : ${ENFORCE_PROTECTION}"
info "enforce_popo               : ${ENFORCE_POPO}"
info "accept_implicit            : ${ACCEPT_IMPLICIT}"
info "enrollment_ca              : ${ENROLLMENT_CA}"
info "protection_certificate     : ${PROTECTION_SERIAL}"

SRVCERT_FLAG=""
TRUSTED_FLAG=""

# Fetch enrollment CA cert as trust anchor (needed so openssl can verify
# server response signatures; without it openssl exits with "missing trust store").
# Strategy:
#   1. If enrollment_ca is set in the DMS, fetch exactly that CA cert.
#   2. Otherwise, fetch ALL CAs from the Lamassu CA API and combine them into
#      a single trust bundle — the correct issuer will be in there.
if [ -n "${ENROLLMENT_CA}" ] && [ "${ENROLLMENT_CA}" != "null" ]; then
    curl -sf "${SERVER}/api/ca/v1/cas/${ENROLLMENT_CA}" \
        | jq -r '.certificate.certificate' \
        | base64 -d \
        > "${WORKDIR}/ca.pem"
    CA_CN=$(openssl x509 -in "${WORKDIR}/ca.pem" -noout -subject 2>/dev/null | sed 's/.*CN=//')
    ok "Enrollment CA cert fetched: CN=${CA_CN}"
    TRUSTED_FLAG="-trusted ${WORKDIR}/ca.pem"
else
    # Fetch all CAs and build a trust bundle (dev/test mode)
    # The .certificate.certificate field is a base64-encoded PEM string.
    info "enrollment_ca not set — building CA trust bundle from all available CAs..."
    curl -sf "${SERVER}/api/ca/v1/cas?page_size=100" \
        | jq -r '.list[].certificate.certificate' \
        | while IFS= read -r b64cert; do echo "${b64cert}" | base64 -d; done \
        > "${WORKDIR}/ca-bundle.pem"
    BUNDLE_COUNT=$(grep -c "BEGIN CERTIFICATE" "${WORKDIR}/ca-bundle.pem" 2>/dev/null || echo 0)
    if [ "${BUNDLE_COUNT}" -gt 0 ]; then
        ok "CA bundle built: ${BUNDLE_COUNT} CA cert(s)"
        TRUSTED_FLAG="-trusted ${WORKDIR}/ca-bundle.pem"
    else
        info "WARNING: No CA certs available — server responses will not be verified."
        TRUSTED_FLAG="-unprotected_errors"
    fi
fi

if [ -z "${PROTECTION_SERIAL}" ] || [ "${PROTECTION_SERIAL}" = "null" ]; then
    info "No DMS-specific protection certificate — server cert verified via CA bundle."
else
    PROTECTION_SERIAL_LC=$(echo "${PROTECTION_SERIAL}" | tr '[:upper:]' '[:lower:]')
    curl -sf "${SERVER}/api/ca/v1/certificates/${PROTECTION_SERIAL_LC}" \
        | jq -r '.certificate' \
        | base64 -d \
        > "${WORKDIR}/srvcert.pem"
    CERT_CN=$(openssl x509 -in "${WORKDIR}/srvcert.pem" -noout -subject 2>/dev/null | sed 's/.*CN=//')
    ok "Protection cert fetched: CN=${CERT_CN}, serial=${PROTECTION_SERIAL}"
    SRVCERT_FLAG="-srvcert ${WORKDIR}/srvcert.pem"
fi

# ── Step 2: Generate bootstrap signer credentials (for IR) ─────────────────────
echo ""
echo "[2/5] Generating bootstrap signer credential (self-signed, for IR)..."

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${WORKDIR}/signer.key" 2>/dev/null
openssl req -new -x509 -key "${WORKDIR}/signer.key" \
    -out "${WORKDIR}/signer.crt" \
    -subj "/CN=bootstrap-signer" \
    -days 1 2>/dev/null
ok "signer.key + signer.crt (CN=bootstrap-signer, 1 day, self-signed)"

# Generate device key (the key whose cert we want the CA to issue)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${WORKDIR}/device.key" 2>/dev/null
ok "device.key (P-256, new enrollment key)"

# ── Step 3: IR — Initial Registration ──────────────────────────────────────────
echo ""
echo "[3/5] IR — Initial Registration (CN=${DEVICE_CN})..."

# Build the openssl cmp args for protection + POPO
# -cert / -key     : protection signer credentials (put in extraCerts automatically
#                    via -extracerts so server can verify the signer)
# -extracerts      : required because openssl does not auto-include EE cert in
#                    extraCerts when it is self-signed (RFC 9483 §3.3)
# -newkey          : device key; openssl auto-adds POPOSigningKey when -newkey != -key
# -implicit_confirm: sends id-it-implicitConfirm in generalInfo; server honours
#                    it when accept_implicit=true → no certConf round-trip needed
IR_EXTRA_FLAGS=""
if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    IR_EXTRA_FLAGS="-implicit_confirm"
fi

openssl cmp \
    -cmd ir \
    -server "${SERVER}" \
    -path "${CMP_PATH}" \
    -cert  "${WORKDIR}/signer.crt" \
    -key   "${WORKDIR}/signer.key" \
    -extracerts "${WORKDIR}/signer.crt" \
    -newkey "${WORKDIR}/device.key" \
    -subject "/CN=${DEVICE_CN}" \
    ${SRVCERT_FLAG} \
    ${TRUSTED_FLAG} \
    ${IR_EXTRA_FLAGS} \
    -certout "${WORKDIR}/device.crt" 2>"${WORKDIR}/ir.log" \
    || { cat "${WORKDIR}/ir.log" >&2; fail "IR failed"; }

DEVICE_SERIAL=$(openssl x509 -in "${WORKDIR}/device.crt" -noout -serial | cut -d= -f2)
DEVICE_ISSUER=$(openssl x509 -in "${WORKDIR}/device.crt" -noout -issuer | sed 's/.*CN=//')
ok "IR succeeded — device.crt issued"
info "  subject : CN=${DEVICE_CN}"
info "  serial  : ${DEVICE_SERIAL}"
info "  issuer  : ${DEVICE_ISSUER}"

# ── Step 4: KUR — Key Update Request ───────────────────────────────────────────
echo ""
echo "[4/5] KUR — Key Update Request (proving identity with device.crt)..."

# Generate a fresh key for the update
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${WORKDIR}/device2.key" 2>/dev/null

# -cert/-key        : the already-enrolled device credential (proves identity)
# -extracerts       : same cert goes into extraCerts for server verification
# -newkey           : the new key to enroll (POPO is auto-generated)
openssl cmp \
    -cmd kur \
    -server "${SERVER}" \
    -path "${CMP_PATH}" \
    -cert  "${WORKDIR}/device.crt" \
    -key   "${WORKDIR}/device.key" \
    -extracerts "${WORKDIR}/device.crt" \
    -newkey "${WORKDIR}/device2.key" \
    ${SRVCERT_FLAG} \
    ${TRUSTED_FLAG} \
    ${IR_EXTRA_FLAGS} \
    -certout "${WORKDIR}/device2.crt" 2>"${WORKDIR}/kur.log" \
    || { cat "${WORKDIR}/kur.log" >&2; fail "KUR failed"; }

DEVICE2_SERIAL=$(openssl x509 -in "${WORKDIR}/device2.crt" -noout -serial | cut -d= -f2)
ok "KUR succeeded — device2.crt issued"
info "  serial  : ${DEVICE2_SERIAL}"
info "  key     : device2.key (new P-256 key)"

# ── Step 5: RR — Revocation Request ────────────────────────────────────────────
echo ""
echo "[5/5] RR — Revocation Request (revoking device2.crt)..."

# -cert/-key/-extracerts : current active credential (device2) to authenticate
# -oldcert              : the cert to revoke (same here)
openssl cmp \
    -cmd rr \
    -server "${SERVER}" \
    -path "${CMP_PATH}" \
    -cert  "${WORKDIR}/device2.crt" \
    -key   "${WORKDIR}/device2.key" \
    -extracerts "${WORKDIR}/device2.crt" \
    -oldcert "${WORKDIR}/device2.crt" \
    ${SRVCERT_FLAG} \
    ${TRUSTED_FLAG} 2>"${WORKDIR}/rr.log" \
    || { cat "${WORKDIR}/rr.log" >&2; fail "RR failed"; }

ok "RR succeeded — device2.crt revoked"

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
echo "========================================================================"
echo -e "${GREEN} ALL STEPS PASSED${RESET}"
echo "========================================================================"
echo ""
echo "  Step    Operation   Cert serial"
echo "  ──────  ──────────  ────────────────────────────────────────"
printf "  IR      issued      %s\n" "${DEVICE_SERIAL}"
printf "  KUR     issued      %s\n" "${DEVICE2_SERIAL}"
echo  "  RR      revoked     ${DEVICE2_SERIAL}"
echo ""
echo "  DMS config:"
echo "    enforce_request_protection : ${ENFORCE_PROTECTION}"
echo "    enforce_popo               : ${ENFORCE_POPO}"
echo "    accept_implicit            : ${ACCEPT_IMPLICIT}"
echo ""
echo "  Files preserved in: ${WORKDIR}"
echo ""
echo "  Notes:"
echo "    - signer.crt is self-signed (bootstrap); the DMS accepts it because"
echo "      client_certificate_settings.chain_level_validation=0 (any cert)."
echo "    - POPO is generated automatically by openssl when -newkey != -key."
echo "    - -extracerts is required: openssl omits EE cert from extraCerts"
echo "      unless explicitly listed (RFC 9483 §3.3 / openssl behaviour)."
echo "    - KUR implicit_confirm flag is optional if the server already"
echo "      includes id-it-implicitConfirm in the IP response."
echo "========================================================================"
