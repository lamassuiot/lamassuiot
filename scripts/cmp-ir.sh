#!/bin/bash
################################################################################
# CMP IR Test
#
# Exercises the complete CMP device lifecycle against a Lamassu DMS configured
# with:
#   - auth_mode: CLIENT_CERTIFICATE (requires signed protection; accepts any
#     client cert at chain_level 0)
#   - enforce_popo: true
#   - accept_implicit: true
#
# Flow:
#   1. Fetch the RA protection certificate from the Lamassu CA API (so the
#      client can verify server responses via -srvcert).
#   2. Generate a self-signed signer cert (bootstrap credential for IR).
#   3. IR  — Initial Registration; produces the first device certificate.
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
DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/.well-known/cmp/p/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-lifecycle}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-device-$(date +%s)"

# Source bootstrap setup helper (provisions a CA + signer cert and patches the
# DMS's client_certificate_settings.validation_cas). With the new server-side
# CMP signer-cert chain validation, a self-signed signer is no longer accepted.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"

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
echo " CMP IR Test"
echo "========================================================================"
echo "  DMS ID  : ${DMS_ID}"
echo "  Server  : ${SERVER}${CMP_PATH}"
echo "  Device  : ${DEVICE_CN}"
echo "  Workdir : ${WORKDIR}"
echo ""

# ── Step 1: Fetch DMS config and protection certificate ─────────────────────────
echo "[1/3] Fetching DMS config and RA protection certificate..."

DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "Cannot reach ${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}"

PROTECTION_SERIAL=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.protection_certificate // empty')
AUTH_MODE=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.auth_mode // "NO_AUTH"')
ENFORCE_POPO=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enforce_popo // false')
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
ENROLLMENT_CA=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.enrollment_ca // empty')

# Protection is required when auth_mode demands a client certificate.
if [ "${AUTH_MODE}" = "CLIENT_CERTIFICATE" ] || [ "${AUTH_MODE}" = "CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK" ]; then
    ENFORCE_PROTECTION="true"
else
    ENFORCE_PROTECTION="false"
fi

info "auth_mode                  : ${AUTH_MODE}"
info "requires protection        : ${ENFORCE_PROTECTION}"
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

# ── Step 2: Provision bootstrap CA + signer (registered with the DMS) ─────────
echo ""
echo "[2/3] Provisioning bootstrap CA + signer cert (registered as ValidationCA)..."

cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" \
    || fail "Bootstrap setup failed"

ok "bootstrap CA ${BOOTSTRAP_CA_ID} added to DMS validation_cas"
ok "signer.key + signer.crt issued by bootstrap CA"

# Refresh DMS_JSON so any later reads see the updated validation_cas.
DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "Cannot re-fetch DMS ${DMS_ID} after bootstrap setup"

# Generate device key (the key whose cert we want the CA to issue)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${WORKDIR}/device.key" 2>/dev/null
ok "device.key (P-256, new enrollment key)"

# ── Step 3: IR — Initial Registration ──────────────────────────────────────────
echo ""
echo "[3/3] IR — Initial Registration (CN=${DEVICE_CN})..."

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
    -verbosity 6 \
    -reqout "${WORKDIR}/ir-req.der" \
    -extracertsout "${WORKDIR}/ip-extracerts.pem" \
    -certout "${WORKDIR}/device.crt" 2>"${WORKDIR}/ir.log" \
    || { cat "${WORKDIR}/ir.log" >&2; fail "IR failed"; }

DEVICE_SERIAL=$(openssl x509 -in "${WORKDIR}/device.crt" -noout -serial | cut -d= -f2)
DEVICE_ISSUER=$(openssl x509 -in "${WORKDIR}/device.crt" -noout -issuer | sed 's/.*CN=//')
DEVICE_NOTBEFORE=$(openssl x509 -in "${WORKDIR}/device.crt" -noout -startdate | cut -d= -f2)
DEVICE_NOTAFTER=$(openssl x509 -in "${WORKDIR}/device.crt" -noout -enddate | cut -d= -f2)

# Extract CMP transaction ID from the saved IR request DER.
# With -dump, asn1parse shows hex bytes for OCTET STRINGs.
# transactionID [4] IMPLICIT OCTET STRING is encoded here as
# cons: cont [4] → prim: OCTET STRING (vs sender/recipient which wrap a SEQUENCE).
TRANSACTION_ID=$(openssl asn1parse -in "${WORKDIR}/ir-req.der" -inform DER -dump 2>/dev/null \
    | awk '
        /cons: cont \[ 4 \]/ { look=1; next }
        look && /prim: OCTET STRING/ { look=0; collect=1; next }
        look { look=0 }
        collect && /[0-9a-fA-F]{4} - / {
            sub(/^.*- /, ""); sub(/   .*$/, ""); gsub(/[- ]/, "")
            print; collect=0
        }
    ' | tr "[:lower:]" "[:upper:]" || true)
[ -z "${TRANSACTION_ID}" ] && TRANSACTION_ID="n/a"

# IR request protection signer info (signer.crt used to protect the IR message)
IR_SIGNER_CN=$(openssl x509 -in "${WORKDIR}/signer.crt" -noout -subject 2>/dev/null \
    | sed 's/.*CN=//')
IR_SIGNER_ISSUER=$(openssl x509 -in "${WORKDIR}/signer.crt" -noout -issuer 2>/dev/null \
    | sed 's/.*CN=//')

# IP response protection signer CN — prefer certs from server extraCerts,
# fall back to the declared DMS srvcert if server omits extraCerts.
IP_SIGNER_CN="n/a"
if [ -f "${WORKDIR}/ip-extracerts.pem" ] && grep -q 'BEGIN CERTIFICATE' "${WORKDIR}/ip-extracerts.pem" 2>/dev/null; then
    IP_SIGNER_CN=$(openssl x509 -in "${WORKDIR}/ip-extracerts.pem" -noout -subject 2>/dev/null \
        | sed 's/.*CN=//')
elif [ -f "${WORKDIR}/srvcert.pem" ]; then
    IP_SIGNER_CN=$(openssl x509 -in "${WORKDIR}/srvcert.pem" -noout -subject 2>/dev/null \
        | sed 's/.*CN=//')
fi

ok "IR succeeded — device.crt issued"
info "  IR request:"
info "    protection signer : ${IR_SIGNER_CN}"
info "    signer issuer     : ${IR_SIGNER_ISSUER}"
info "  IP response:"
info "    protection signer : ${IP_SIGNER_CN}"
info "    txn ID            : ${TRANSACTION_ID}"
info "  issued cert:"
info "    subject    : CN=${DEVICE_CN}"
info "    serial     : ${DEVICE_SERIAL}"
info "    issuer     : ${DEVICE_ISSUER}"
info "    not before : ${DEVICE_NOTBEFORE}"
info "    not after  : ${DEVICE_NOTAFTER}"

# ── Summary ─────────────────────────────────────────────────────────────────────
echo ""
echo "========================================================================"
echo -e "${GREEN} ALL STEPS PASSED${RESET}"
echo "========================================================================"
echo ""
echo "  Step    Operation   Cert serial"
echo "  ──────  ──────────  ────────────────────────────────────────"
printf "  IR      issued      %s\n" "${DEVICE_SERIAL}"
echo ""
echo "  DMS config:"
echo "    auth_mode                  : ${AUTH_MODE}"
    echo "    requires protection        : ${ENFORCE_PROTECTION}"
echo "    enforce_popo               : ${ENFORCE_POPO}"
echo "    accept_implicit            : ${ACCEPT_IMPLICIT}"
echo ""
echo "  Files preserved in: ${WORKDIR}"
echo ""
echo "  Notes:"
echo "    - signer.crt is issued by bootstrap CA ${BOOTSTRAP_CA_ID}, which was"
echo "      provisioned in Lamassu and added to the DMS's"
echo "      client_certificate_settings.validation_cas before the IR. The"
echo "      DMS Manager chain-validates the CMP signer cert against this list"
echo "      (mirroring EST mTLS authentication)."
echo "    - POPO is generated automatically by openssl when -newkey != -key."
echo "    - -extracerts is required: openssl omits EE cert from extraCerts"
echo "      unless explicitly listed (RFC 9483 §3.3 / openssl behaviour)."
echo "========================================================================"
