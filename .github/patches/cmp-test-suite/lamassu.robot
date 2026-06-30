# Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation     Configuration for running the CMP test suite against a local Lamassu instance.
...               Requires the monolithic server at http://localhost:8080 and the
...               bootstrap signer credentials at /tmp/cmp-bootstrap/ (run
...               scripts/cmp-bootstrap-setup.sh before executing tests).


*** Variables ***
# CMP endpoint: /.well-known/cmp/p/<dms-id>
${CA_CMP_URL}    http://localhost:8080/.well-known/cmp/p/sample-cmp-dms
${CA_BASE_URL}   http://localhost:8080/.well-known/cmp/p/sample-cmp-dms
# DMS ID is the path discriminator; body type suffix not needed.
${APPEND_PKIBODY_URL_SUFFIX}    ${False}

# No pre-issued cert/key — the suite setup enrolls one via the bootstrap signer.
${ISSUED_KEY}    ${None}
${ISSUED_CERT}   ${None}
# Init suffix not required — the URL already contains the DMS ID.
${INIT_SUFFIX}   ${None}
# Bootstrap signer credentials created by cmp-bootstrap-setup.sh
${INITIAL_KEY_PATH}    /tmp/cmp-bootstrap/signer.key
${INITIAL_CERT_PATH}   /tmp/cmp-bootstrap/signer.crt
${INITIAL_KEY_PASSWORD}   ${None}


# Lamassu DMS uses CLIENT_CERTIFICATE auth — MAC protection is not available.
${PRESHARED_SECRET}    SiemensIT
${SENDER}              CN=cmp-bootstrap-signer
${RECIPIENT}           CN=sample-cmp-dms
# Distinct from the suite's global protection cert (CN=Hans Mustermann, enrolled
# once by Set Up Test Suite). Using a separate CN here means per-test enrollments
# don't re-enroll — and thus don't revoke (replaceable enrollment) — the global
# protection cert, which would otherwise cascade-fail every later test.
# Trade-off: KUR tests, which hardcode subject CN=Hans Mustermann, can't find
# this device and fail the §4.1.3 active-cert binding. See known-limitations note.
${DEFAULT_X509NAME}    CN=lamassu-cmp-client

##### About Issuing:

# Implicit confirmation allowed.
${ALLOW_IMPLICIT_CONFIRM}  ${True}

# Keep a single sender identity per test run.
${ALLOW_ONLY_ONE_SENDER}   ${True}
# for test cases are only the same keys can be used to save resources.
${ALLOW_IR_SAME_KEY}       ${True}
${IRELEVANT_messageTime}    ${FALSE}
${SUPPORT_DIRECTORY_CHOICE_FOR_MAC_PROTECTION}   ${False}

##### Security
${ENC_CERT_PASSWORD}    ${NONE}
${ENC_CERT_EE_KEY}      ${NONE}

${EXAMPLES_KUR_GEN}    10
${GATHER_NONCES_FROM_MSG_BODIES}    ip,cp,kup,rp,error
# Lamassu uses CLIENT_CERTIFICATE — MAC is not supported.
${ALLOW_MAC_PROTECTION}   ${False}
${STRICT_MAC_VALIDATION}   ${False}

${EXTENDED_KEY_USAGE_STRICTNESS}   LAX
${KEY_USAGE_STRICTNESS}   LAX
${STRICT}   ${False}
# LightweightCMP (RFC 9483) mode.
${LWCMP}   ${True}
${ENFORCE_RFC9481}   ${True}

${ALLOW_NULL_INSTEAD_OF_ABSENT}   ${False}

##### About Algorithms
${DEFAULT_KEY_LENGTH}    2048
${DEFAULT_ALGORITHM}    rsa
${DEFAULT_ECC_CURVE}   secp256r1
${DEFAULT_MAC_ALGORITHM}   password_based_mac
${DEFAULT_KGA_ALGORITHM}   rsa
${DEFAULT_PQ_SIG_ALGORITHM}   ml-dsa-44
${DEFAULT_PQ_KEM_ALGORITHM}   ml-kem-512
${DEFAULT_KEY_AGREEMENT_ALG}   x25519
${DEFAULT_KEY_ENCIPHERMENT_ALG}   ml-kem-768
${DEFAULT_ML_DSA_ALG}    ml-dsa-87
${DEFAULT_ML_KEM_ALG}    ml-kem-768

##### Extra Issuing Logic
${CA_RSA_ENCR_CERT}    ${None}
${CA_X25519_CERT}   ${None}
${CA_X448_CERT}     ${None}
${CA_ECC_CERT}      ${None}
${CA_HYBRID_KEM_CERT}   ${None}
${CA_KEM_CERT}     ${None}

##### About CertTemplate
${ALLOWED_ALGORITHM}   ed25519,rsa,ecc,ed448,x25519,x448
${ALLOW_ISSUING_OF_CA_CERTS}  ${False}
${ALLOW_CMP_EKU_EXTENSION}  ${False}

##### Section 3
${FAILINFO_MUST_BE_CORRECT}=    True
${MAX_ALLOW_TIME_INTERVAL_RECEIVED}  ${-500}

# DSA is not allowed by RFC9483.
${DSA_KEY}         ${None}
${DSA_KEY_PASSWORD}   ${None}
${DSA_CERT}        ${None}

# Device certificate and key (None means not provided).
${DEVICE_CERT_CHAIN}   ${None}
${DEVICE_KEY}  ${None}
${DEVICE_KEY_PASSWORD}   ${None}

##### Section 4
${ALLOW_P10CR_MAC_BASED}   ${False}
${ALLOW_CR_MAC_BASED}   ${False}
${ALLOW_IR_MAC_BASED}   ${False}
${ALLOW_KUR_SAME_KEY}    ${True}
${LARGE_KEY_SIZE}    ${False}
${ALLOW_CERT_CONF}    ${False}

# Section 4.1.6
${ALLOW_KGA}   ${False}
${ALLOW_KGA_RAW_KEYS}   ${False}

# Section 4.2
${REVOCATION_STRICT_CHECK}    ${False}
${REVOKED_WAIT_TIME}   10s
${UPDATE_WAIT_TIME}   3s
${WAIT_UNTIL_UPDATED_CONFIRMATION_IS_EXPIRED}   15s

# Section 4.3
${ALLOW_MAC_PROTECTED_SUPPORT_MSG}   ${False}
${ALLOW_SUPPORT_MESSAGES}   ${True}
${CRL_FILEPATH}    ${None}
${CRL_CERT_IDP}  ${False}

${OLD_ROOT_CERT}   ${None}
${CERT_PROFILE}    ${None}

${ALLOWED_TIME_INTERVAL}   ${300}

${ALLOW_CRL_CHECK}   ${False}
${REVOKE_CERT_ON_ERROR}  ${False}
${REVOKE_CERT_ON_LATE_CONFIRMATION}  ${False}

# Device certificate
${DEVICE_CERT}   ${None}

# Section 5.2 and 5.3
${OTHER_TRUSTED_PKI_KEY}    ${None}
${OTHER_TRUSTED_PKI_CERT}    ${None}
${ALLOW_UNPROTECTED_INNER_MESSAGE}    ${None}
${RA_CERT_CHAIN_DIR}    ${None}
${RA_CERT_CHAIN_PATH}   ${None}

${RR_CERT_FOR_TRUSTED}   ${None}

${TRUSTED_CA_CERT}      ${None}
${TRUSTED_CA_KEY}       ${None}
${TRUSTED_CA_KEY_PASSWORD}   ${None}
${TRUSTED_CA_DIR}            ${None}

# Hybrid Endpoints (not configured for Lamassu)
${PQ_ISSUING_SUFFIX}    ${None}
${PQ_STATEFUL_ISSUING_SUFFIX}   ${None}
${URI_RELATED_CERT}   ${None}
${NEG_URI_RELATED_CERT}   ${None}
${ISSUING_SUFFIX}    ${None}
${COMPOSITE_URL_PREFIX}    ${None}
${CATALYST_SIGNATURE}    ${None}
${SUN_HYBRID_SUFFIX}    ${None}
${CHAMELEON_SUFFIX}    ${None}
${RELATED_CERT_SUFFIX}    ${None}
${MULTI_AUTH_SUFFIX}    ${None}
${CERT_DISCOVERY_SUFFIX}    ${None}
