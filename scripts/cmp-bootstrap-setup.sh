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
#   BOOTSTRAP_CRL_FILE      — path to the bootstrap CA's CRL (PEM), if the VA
#                             published it in time; unset otherwise
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

    # 3a. CRL for the `CRL Update Retrieval` tests (RFC 9483 §4.3.4). The
    #     bootstrap CA gets a VA role (and its first CRL) asynchronously via the
    #     event bus right after creation, so poll the VA's `/crl/<ca-ski>`
    #     endpoint for a few seconds before giving up. The signer cert above
    #     already carries a CRLDistributionPoints extension for this same CA
    #     (every cert Lamassu issues does, via addDistributionPoints), so it
    #     doubles as CRL_CERT_IDP — no dedicated cert/extension needed.
    local ca_ski crl_ok=0
    ca_ski=$(echo "${ca_resp}" | jq -r '.certificate.subject_key_id // empty')
    if [ -n "${ca_ski}" ]; then
        for _ in $(seq 1 15); do
            if curl -sf "${server}/api/va/crl/${ca_ski}" -o "${workdir}/bootstrap-ca.crl.der" 2>/dev/null \
                && [ -s "${workdir}/bootstrap-ca.crl.der" ]; then
                crl_ok=1
                break
            fi
            sleep 1
        done
    fi
    if [ "${crl_ok}" = "1" ] && openssl crl -inform DER -in "${workdir}/bootstrap-ca.crl.der" \
        -outform PEM -out "${workdir}/bootstrap-ca.crl" 2>/dev/null; then
        export BOOTSTRAP_CRL_FILE="${workdir}/bootstrap-ca.crl"
    else
        echo "cmp_bootstrap_setup: could not fetch bootstrap CA CRL (CRL Update Retrieval With CRL File test may skip)" >&2
    fi

    # 3b. RA credential for RFC 9483 §5.2.3.2 raVerified tests: a certificate
    #     carrying id-kp-cmcRA (1.3.6.1.5.5.7.3.28), issued by the bootstrap CA so
    #     it chains to a DMS ValidationCA. Lamassu accepts a raVerified POPO only
    #     when the message-protection signer is such a trusted RA. Also used as
    #     the added-protection RA (OTHER_TRUSTED_PKI) for the nested tests.
    local ra_profile_resp ra_profile_id ra_sign_resp ra_dir="${workdir}/ra-certs"
    mkdir -p "${ra_dir}"
    ra_profile_resp=$(curl -sf -X POST "${server}/api/ca/v1/profiles" \
        -H 'Content-Type: application/json' \
        -d '{
            "name": "cmp-bootstrap-ra-profile-'"${stamp}"'",
            "description": "RA profile with id-kp-cmcRA for raVerified tests",
            "validity": {"type": "Duration", "duration": "365d"},
            "honor_key_usage": false,
            "key_usage": ["DigitalSignature"],
            "honor_extended_key_usages": false,
            "extended_key_usages": [],
            "extra_extended_key_usage_oids": ["1.3.6.1.5.5.7.3.28"]
        }') && ra_profile_id=$(echo "${ra_profile_resp}" | jq -r '.id')
    if [ -n "${ra_profile_id:-}" ] && [ "${ra_profile_id}" != "null" ]; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${workdir}/ra.key" 2>/dev/null
        openssl req -new -key "${workdir}/ra.key" -out "${workdir}/ra.csr" -subj "/CN=cmp-trusted-ra" 2>/dev/null
        local ra_csr_b64; ra_csr_b64=$(openssl req -in "${workdir}/ra.csr" -outform PEM 2>/dev/null | base64 -w0)
        ra_sign_resp=$(curl -sf -X POST "${server}/api/ca/v1/cas/${ca_id}/certificates/sign" \
            -H 'Content-Type: application/json' \
            -d '{"csr": "'"${ra_csr_b64}"'", "profile_id": "'"${ra_profile_id}"'"}')
        if [ -n "${ra_sign_resp}" ]; then
            echo "${ra_sign_resp}" | jq -r '.certificate' | base64 -d > "${ra_dir}/ra.crt"
            # Bootstrap CA cert completes the RA chain for the suite's
            # `Build Cert Chain From Dir` (RA -> bootstrap CA). The CA object nests
            # the base64 PEM at .certificate.certificate. Only write it if
            # non-empty — an empty file would break the suite's chain parser.
            local ca_pem; ca_pem=$(echo "${ca_resp}" | jq -r '.certificate.certificate // empty' | base64 -d 2>/dev/null)
            if [ -n "${ca_pem}" ]; then
                printf '%s\n' "${ca_pem}" > "${ra_dir}/bootstrap-ca.crt"
            fi
            export BOOTSTRAP_RA_KEY="${workdir}/ra.key"
            export BOOTSTRAP_RA_CERT="${ra_dir}/ra.crt"
            export BOOTSTRAP_RA_DIR="${ra_dir}"
        fi
    fi
    [ -f "${ra_dir}/ra.crt" ] || echo "cmp_bootstrap_setup: RA cert provisioning skipped (raVerified/nested tests may fail)" >&2

    # 3c. Two-level chain (root -> intermediate) for the "reject signature-
    #     protected PKIMessage without complete certificate chain" test
    #     (RFC 9483 §3.3): that test only means something when the signer's
    #     chain has an intermediate to omit from extraCerts. The bootstrap CA
    #     above is a single-level root, so a dedicated chain is built here:
    #     only the ROOT is added to the DMS's ValidationCAs (section 4 below),
    #     the signer cert is issued by the INTERMEDIATE, so submitting just
    #     the signer cert (no intermediate) in extraCerts genuinely fails
    #     chain building, and including the intermediate genuinely succeeds.
    local chain_profile_resp chain_profile_id chain_root_resp chain_root_id chain_int_resp chain_int_id
    local chain_dir="${workdir}/chain-certs"
    mkdir -p "${chain_dir}"
    chain_profile_resp=$(curl -sf -X POST "${server}/api/ca/v1/profiles" \
        -H 'Content-Type: application/json' \
        -d '{
            "name": "cmp-bootstrap-chain-profile-'"${stamp}"'",
            "description": "Auto-created by cmp-bootstrap-setup.sh for the two-level chain test",
            "validity": {"type": "Duration", "duration": "365d"},
            "honor_key_usage": false,
            "key_usage": []
        }') && chain_profile_id=$(echo "${chain_profile_resp}" | jq -r '.id')
    if [ -n "${chain_profile_id:-}" ] && [ "${chain_profile_id}" != "null" ]; then
        chain_root_resp=$(curl -sf -X POST "${server}/api/ca/v1/cas" \
            -H 'Content-Type: application/json' \
            -d '{
                "subject": {"common_name": "cmp-chain-root-'"${stamp}"'"},
                "key_metadata": {"type": "ECDSA", "bits": 256},
                "ca_expiration": {"type": "Duration", "duration": "365d"},
                "profile_id": "'"${chain_profile_id}"'",
                "metadata": {"created_by": "cmp-bootstrap-setup.sh"}
            }') && chain_root_id=$(echo "${chain_root_resp}" | jq -r '.id')
        if [ -n "${chain_root_id:-}" ] && [ "${chain_root_id}" != "null" ]; then
            chain_int_resp=$(curl -sf -X POST "${server}/api/ca/v1/cas" \
                -H 'Content-Type: application/json' \
                -d '{
                    "parent_id": "'"${chain_root_id}"'",
                    "subject": {"common_name": "cmp-chain-intermediate-'"${stamp}"'"},
                    "key_metadata": {"type": "ECDSA", "bits": 256},
                    "ca_expiration": {"type": "Duration", "duration": "365d"},
                    "profile_id": "'"${chain_profile_id}"'",
                    "metadata": {"created_by": "cmp-bootstrap-setup.sh"}
                }') && chain_int_id=$(echo "${chain_int_resp}" | jq -r '.id')
        fi
        if [ -n "${chain_int_id:-}" ] && [ "${chain_int_id}" != "null" ]; then
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${chain_dir}/chain-signer.key" 2>/dev/null
            openssl req -new -key "${chain_dir}/chain-signer.key" -out "${chain_dir}/chain-signer.csr" \
                -subj "/CN=cmp-chain-signer" 2>/dev/null
            local chain_csr_b64; chain_csr_b64=$(openssl req -in "${chain_dir}/chain-signer.csr" -outform PEM 2>/dev/null | base64 -w0)
            local chain_sign_resp
            chain_sign_resp=$(curl -sf -X POST "${server}/api/ca/v1/cas/${chain_int_id}/certificates/sign" \
                -H 'Content-Type: application/json' \
                -d '{"csr": "'"${chain_csr_b64}"'", "profile_id": "'"${chain_profile_id}"'"}')
            if [ -n "${chain_sign_resp}" ]; then
                echo "${chain_sign_resp}" | jq -r '.certificate' | base64 -d > "${chain_dir}/chain-signer.crt"
                local chain_int_pem; chain_int_pem=$(echo "${chain_int_resp}" | jq -r '.certificate.certificate // empty' | base64 -d 2>/dev/null)
                [ -n "${chain_int_pem}" ] && printf '%s\n' "${chain_int_pem}" > "${chain_dir}/chain-intermediate.crt"
                export CHAIN_ROOT_CA_ID="${chain_root_id}"
                export CHAIN_SIGNER_KEY="${chain_dir}/chain-signer.key"
                export CHAIN_SIGNER_CERT="${chain_dir}/chain-signer.crt"
                export CHAIN_INTERMEDIATE_CERT="${chain_dir}/chain-intermediate.crt"
            fi
        fi
    fi
    [ -f "${chain_dir}/chain-signer.crt" ] || echo "cmp_bootstrap_setup: chain CA provisioning skipped (incomplete-chain test may stay skipped)" >&2

    # 3d. Foreign-DMS device for the "CA or RA MUST Reject Not Authorized
    #     Sender" test (RFC 9483 §3.5): a device pre-registered under an
    #     unrelated DMS ID. Device Manager's CreateDevice does not validate
    #     that dms_id refers to a real DMS, so the "other" DMS need not
    #     actually exist. An ir naming this same CommonName, even though
    #     protected by the legitimate bootstrap signer (trusted, sender-
    #     matched), must still be rejected: the signer just has no claim to
    #     this identity. Non-fatal — a rerun against a live server hits 409
    #     on the already-created device, which is the same precondition.
    local foreign_device_id="cmp-foreign-owned-device"
    curl -sf -X POST "${server}/api/devmanager/v1/devices" \
        -H 'Content-Type: application/json' \
        -d '{
            "id": "'"${foreign_device_id}"'",
            "dms_id": "cmp-bootstrap-other-dms"
        }' > /dev/null 2>&1 || true
    if curl -sf "${server}/api/devmanager/v1/devices/${foreign_device_id}" > /dev/null 2>&1; then
        export NOT_AUTHORIZED_SENDER_DEVICE_CN="${foreign_device_id}"
    else
        echo "cmp_bootstrap_setup: foreign-DMS device provisioning failed (Not Authorized Sender test may fail)" >&2
    fi

    # 4. Patch the DMS: append the bootstrap CA to ValidationCAs (idempotent,
    #    dedup-on-PUT via `unique`). UpdateDMS replaces the whole resource so
    #    we read the current state and mutate just the field we care about.
    dms_resp=$(curl -sf "${server}/api/dmsmanager/v1/dms/${dms_id}") || {
        echo "cmp_bootstrap_setup: failed to fetch DMS ${dms_id}" >&2
        return 1
    }
    #    Three CAs must be trusted as message-protection signers:
    #      - the bootstrap CA (initial enrollment, openssl -cert/-extracerts)
    #      - the enrollment CA itself, so that re-enrollment/KUR requests
    #        protected with a previously Lamassu-issued cert still validate
    #        (the standard CMP renewal flow, RFC 9483 §4.1.3).
    #      - the chain-test ROOT CA only (never the intermediate) — see 3c
    #        above; the intermediate must come from extraCerts, not the trust
    #        store, for the incomplete-chain test to mean anything.
    #    EnableReplaceableEnrollment is also turned on so re-running the suite
    #    (which reuses the same subject CN) can supersede the prior cert.
    #    server_key_gen_enabled opts this DMS in to RFC 9483 §4.1.6 central key
    #    generation, which the compliance suite's Kga tests (Key Transport /
    #    Key Agreement, via ir and kur) exercise; it defaults to false on a
    #    fresh DMS so operators must opt in explicitly.
    patched_dms=$(echo "${dms_resp}" | jq --arg ca "${ca_id}" --arg chainca "${CHAIN_ROOT_CA_ID:-}" '
        ( .settings.enrollment_settings.enrollment_ca ) as $enrollca
        | .settings.enrollment_settings.lwc_rfc9483_settings.client_certificate_settings.validation_cas =
            (((.settings.enrollment_settings.lwc_rfc9483_settings.client_certificate_settings.validation_cas) // [])
                + [$ca] + (if $enrollca then [$enrollca] else [] end)
                + (if $chainca != "" then [$chainca] else [] end) | unique)
        | .settings.enrollment_settings.enable_replaceable_enrollment = true
        | .settings.enrollment_settings.lwc_rfc9483_settings.server_key_gen_enabled = true
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
    if [ -n "${NOT_AUTHORIZED_SENDER_DEVICE_CN:-}" ]; then
        echo "NOT_AUTHORIZED_SENDER_DEVICE_CN=${NOT_AUTHORIZED_SENDER_DEVICE_CN}"
    fi
    if [ -n "${BOOTSTRAP_CRL_FILE:-}" ]; then
        echo "BOOTSTRAP_CRL_FILE=${BOOTSTRAP_CRL_FILE}"
    fi
    if [ -n "${CHAIN_SIGNER_CERT:-}" ]; then
        echo "CHAIN_ROOT_CA_ID=${CHAIN_ROOT_CA_ID}"
        echo "CHAIN_SIGNER_KEY=${CHAIN_SIGNER_KEY}"
        echo "CHAIN_SIGNER_CERT=${CHAIN_SIGNER_CERT}"
        echo "CHAIN_INTERMEDIATE_CERT=${CHAIN_INTERMEDIATE_CERT}"
    fi
fi
