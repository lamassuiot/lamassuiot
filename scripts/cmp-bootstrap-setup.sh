#!/bin/bash
################################################################################
# CMP Bootstrap Setup (sourceable helper)
#
# Provisions everything needed for a CMP client to authenticate against a
# Lamassu DMS with the new request-side validation:
#
#   1. Create a fresh "bootstrap" CA in Lamassu (its own issuance profile too).
#   2. Generate an EE key + CSR and have the bootstrap CA sign it. This EE
#      cert is what the CMP client passes via openssl -cert / -extracerts as
#      the message-protection signer.
#   3. Append the bootstrap CA's ID to the DMS's
#      settings.enrollment_settings.lwc_rfc9483_settings.client_certificate_settings.validation_cas
#      so the DMS Manager chain-validates the signer against it (mirroring the
#      EST mTLS auth path).
#
# This script is meant to be sourced from a CMP scenario script:
#
#   . scripts/cmp-bootstrap-setup.sh "${SERVER}" "${DMS_ID}" "${WORKDIR}"
#
# On return it exports:
#   BOOTSTRAP_CA_ID         — CA ID added to the DMS's ValidationCAs
#   BOOTSTRAP_SIGNER_KEY    — path to the signer EE private key (PEM)
#   BOOTSTRAP_SIGNER_CERT   — path to the signer EE certificate (PEM)
#
# Required tools: curl, jq, openssl, base64.
#
# Required env (or pass as positional args):
#   SERVER   — Lamassu base URL (e.g. http://localhost:8080)
#   DMS_ID   — existing DMS ID
#   WORKDIR  — writable directory for signer.key / signer.crt
################################################################################

cmp_bootstrap_setup() {
    local server="$1"
    local dms_id="$2"
    local workdir="$3"

    if [ -z "${server}" ] || [ -z "${dms_id}" ] || [ -z "${workdir}" ]; then
        echo "cmp_bootstrap_setup: requires SERVER, DMS_ID and WORKDIR" >&2
        return 2
    fi

    local stamp; stamp=$(date +%s%N)
    local profile_resp profile_id ca_resp ca_id sign_resp dms_resp patched_dms

    # 1. Issuance profile for the bootstrap CA. 365d covers signer-cert lifetime.
    profile_resp=$(curl -sf -X POST "${server}/api/ca/v1/profiles" \
        -H 'Content-Type: application/json' \
        -d '{
            "name": "cmp-bootstrap-profile-'"${stamp}"'",
            "description": "Auto-created by cmp-bootstrap-setup.sh",
            "validity": {"type": "Duration", "duration": "365d"},
            "honor_key_usage": false,
            "key_usage": []
        }') || {
        echo "cmp_bootstrap_setup: failed to create issuance profile" >&2
        return 1
    }
    profile_id=$(echo "${profile_resp}" | jq -r '.id')
    [ -n "${profile_id}" ] && [ "${profile_id}" != "null" ] || {
        echo "cmp_bootstrap_setup: issuance profile id missing in response: ${profile_resp}" >&2
        return 1
    }

    # 2. Bootstrap CA itself. P-256 / 1 year is plenty for a test signer chain.
    ca_resp=$(curl -sf -X POST "${server}/api/ca/v1/cas" \
        -H 'Content-Type: application/json' \
        -d '{
            "subject": {"common_name": "cmp-bootstrap-'"${stamp}"'"},
            "key_metadata": {"type": "ECDSA", "bits": 256},
            "ca_expiration": {"type": "Duration", "duration": "365d"},
            "profile_id": "'"${profile_id}"'",
            "metadata": {"created_by": "cmp-bootstrap-setup.sh"}
        }') || {
        echo "cmp_bootstrap_setup: failed to create bootstrap CA" >&2
        return 1
    }
    ca_id=$(echo "${ca_resp}" | jq -r '.id')
    [ -n "${ca_id}" ] && [ "${ca_id}" != "null" ] || {
        echo "cmp_bootstrap_setup: bootstrap CA id missing in response: ${ca_resp}" >&2
        return 1
    }

    # 3. Signer key + CSR, then ask the bootstrap CA to sign it. The signed
    #    cert's PEM is returned as a base64-encoded blob in `.certificate`.
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "${workdir}/signer.key" 2>/dev/null
    openssl req -new -key "${workdir}/signer.key" \
        -out "${workdir}/signer.csr" \
        -subj "/CN=cmp-bootstrap-signer" 2>/dev/null

    local csr_b64
    csr_b64=$(openssl req -in "${workdir}/signer.csr" -outform PEM 2>/dev/null | base64 -w0)

    sign_resp=$(curl -sf -X POST "${server}/api/ca/v1/cas/${ca_id}/certificates/sign" \
        -H 'Content-Type: application/json' \
        -d '{"csr": "'"${csr_b64}"'", "profile_id": "'"${profile_id}"'"}') || {
        echo "cmp_bootstrap_setup: failed to sign bootstrap signer CSR" >&2
        return 1
    }
    echo "${sign_resp}" | jq -r '.certificate' | base64 -d > "${workdir}/signer.crt"

    # 4. Patch the DMS: append the bootstrap CA to ValidationCAs (idempotent,
    #    dedup-on-PUT via `unique`). UpdateDMS replaces the whole resource so
    #    we read the current state and mutate just the field we care about.
    dms_resp=$(curl -sf "${server}/api/dmsmanager/v1/dms/${dms_id}") || {
        echo "cmp_bootstrap_setup: failed to fetch DMS ${dms_id}" >&2
        return 1
    }
    patched_dms=$(echo "${dms_resp}" | jq --arg ca "${ca_id}" '
        .settings.enrollment_settings.lwc_rfc9483_settings.client_certificate_settings.validation_cas =
            (((.settings.enrollment_settings.lwc_rfc9483_settings.client_certificate_settings.validation_cas) // []) + [$ca] | unique)
    ')
    curl -sf -X PUT "${server}/api/dmsmanager/v1/dms/${dms_id}" \
        -H 'Content-Type: application/json' \
        -d "${patched_dms}" > /dev/null || {
        echo "cmp_bootstrap_setup: failed to update DMS ${dms_id} with bootstrap CA" >&2
        return 1
    }

    export BOOTSTRAP_CA_ID="${ca_id}"
    export BOOTSTRAP_SIGNER_KEY="${workdir}/signer.key"
    export BOOTSTRAP_SIGNER_CERT="${workdir}/signer.crt"
    return 0
}

# Allow the helper to also be invoked directly for ad-hoc setup:
#   ./scripts/cmp-bootstrap-setup.sh SERVER DMS_ID WORKDIR
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    set -euo pipefail
    # Default values — override by passing positional args or setting env vars.
    : "${SERVER:=http://localhost:8080}"
    : "${DMS_ID:=sample-cmp-dms}"
    : "${WORKDIR:=/tmp/cmp-bootstrap}"
    mkdir -p "${WORKDIR}"
    cmp_bootstrap_setup "${1:-${SERVER}}" "${2:-${DMS_ID}}" "${3:-${WORKDIR}}"
    echo "BOOTSTRAP_CA_ID=${BOOTSTRAP_CA_ID}"
    echo "BOOTSTRAP_SIGNER_KEY=${BOOTSTRAP_SIGNER_KEY}"
    echo "BOOTSTRAP_SIGNER_CERT=${BOOTSTRAP_SIGNER_CERT}"
fi
