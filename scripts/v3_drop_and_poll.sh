#!/bin/bash
################################################################################
# CMP v3 (cmp2021) Drop-and-Poll demo
#
# Same lost-response recovery scenario as cmp-drop-and-poll.sh, but every wire
# message in the transaction declares pvno=cmp2021(3) instead of cmp2000(2).
# Verifies that the Lamassu CMP controller correctly echoes pvno=3 on every
# response per RFC 9810 §7 line 3754:
#
#   "the version of the response message MUST be the same as the received
#    version"
#
# Flow:
#   1. Build an IR DER with openssl (pvno=2, the only version openssl emits).
#   2. PATCH the IR DER in-place to set pvno=3, then RE-SIGN it — patching the
#      pvno byte invalidates openssl's signature, and DMSes that enforce
#      request protection will reject the bare patched DER.
#   3. POST the patched + re-signed IR via curl; discard the response.
#   4. Send a pvno=3 pollReq (built inline) — server must redeliver the cert
#      with pvno=3.
#   5. If the DMS uses explicit confirmation, send a pvno=3 certConf —
#      server must reply with pkiConf (pvno=3) and transition CONFIRMED.
#
# Why we don't use cmp_pollreq.py / cmp_certconf.py directly
# ----------------------------------------------------------
# Those helpers hard-code pvno=2. To keep them unmodified, we build pollReq
# and certConf inline in this script (small python heredocs) so we can emit
# pvno=3 cleanly without re-signing surgery.
#
# Prerequisites
# -------------
#   - Lamassu monolithic dev server on localhost:8080
#   - A DMS (default sample-cmp-dms)
#   - python3, openssl 3.x, curl, jq
#
# Usage:
#   ./scripts/v3_drop_and_poll.sh [DMS_ID [SERVER]]
################################################################################
set -euo pipefail

DMS_ID="${1:-${DMS_ID:-sample-cmp-dms}}"
SERVER="${2:-${SERVER:-http://localhost:8080}}"
CMP_PATH="/api/dmsmanager/.well-known/cmp/p/${DMS_ID}"
WORKDIR="${WORKDIR:-/tmp/cmp-v3-drop-poll}"
mkdir -p "${WORKDIR}"
DEVICE_CN="cmp-v3-drop-$(date +%s)"
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

# Returns the PKIBody CHOICE tag of a DER-encoded PKIMessage on stdout.
# Used after every server interaction to disambiguate IP (cert) from error.
cmp_body_tag() {
    python3 - "$1" <<'PYEOF'
import sys
with open(sys.argv[1], "rb") as f:
    d = f.read()
# Walk outer SEQUENCE then skip entire header TLV; body is the next TLV.
def skip(buf, o):
    """Return offset just past tag+length (= start of content)."""
    o += 1
    n = buf[o]; o += 1
    if n & 0x80:
        o += n & 0x7F
    return o
def skip_tlv(buf, o):
    """Skip an entire TLV (tag+length+content) and return offset of next element."""
    o += 1  # tag
    n = buf[o]; o += 1
    if n < 128:
        return o + n
    nb = n & 0x7F
    length = int.from_bytes(buf[o:o+nb], "big")
    return o + nb + length
o = skip(d, 0)       # past outer SEQUENCE tag+len = start of outer content
o = skip_tlv(d, o)   # skip entire PKIHeader TLV = body tag position
# d[o] is the body's first byte: a context-specific tag like 0xA0 + tag_num
tag_byte = d[o]
print(tag_byte & 0x1F)
PYEOF
}

# Returns the pvno integer (1-3) on stdout for a DER-encoded PKIMessage.
cmp_pvno() {
    python3 - "$1" <<'PYEOF'
import sys
with open(sys.argv[1], "rb") as f:
    d = f.read()
def skip(buf, o):
    o += 1
    n = buf[o]; o += 1
    if n & 0x80:
        o += n & 0x7F
    return o
o = skip(d, 0); o = skip(d, o)
print(d[o+2])
PYEOF
}

# Returns the statusString of an error PKIMessage on stdout — useful for
# diagnostics when the server rejects our request.
cmp_error_reason() {
    python3 - "$1" <<'PYEOF'
import sys
with open(sys.argv[1], "rb") as f:
    d = f.read()
# Find the first UTF8String (tag 0x0C) inside the message — that's the
# statusString contents.  Brutally simple, but sufficient for diagnostics.
i = d.find(b"\x0C")
while i >= 0:
    if i + 1 < len(d):
        ln = d[i+1]
        if ln < 128 and i + 2 + ln <= len(d):
            try:
                s = d[i+2:i+2+ln].decode("utf-8")
                if s and all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in s.encode("utf-8")):
                    print(s)
                    sys.exit(0)
            except UnicodeDecodeError:
                pass
    i = d.find(b"\x0C", i+1)
print("(error reason not found)")
PYEOF
}

echo "========================================================================"
echo " CMP v3 (cmp2021) Drop-and-Poll Demo"
echo "========================================================================"
echo "  DMS         : ${DMS_ID}"
echo "  Server      : ${SERVER}${CMP_PATH}"
echo "  Device CN   : ${DEVICE_CN}"
echo "  Workdir     : ${WORKDIR}"
echo "  CMP pvno    : 3 (cmp2021)"
echo ""

# ── Step 1: DMS config ────────────────────────────────────────────────────────
echo "[1/9] Reading DMS configuration..."
DMS_JSON=$(curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}") \
    || fail "cannot fetch DMS ${DMS_ID} at ${SERVER}"
AUTH_MODE=$(echo "${DMS_JSON}"       | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.auth_mode // "NO_AUTH"')
ACCEPT_IMPLICIT=$(echo "${DMS_JSON}" | jq -r '.settings.enrollment_settings.lwc_rfc9483_settings.accept_implicit // false')
ENROLLMENT_CA=$(echo "${DMS_JSON}"   | jq -r '.settings.enrollment_settings.enrollment_ca // empty')
if [ "${AUTH_MODE}" = "CLIENT_CERTIFICATE" ] || [ "${AUTH_MODE}" = "CLIENT_CERTIFICATE_AND_EXTERNAL_WEBHOOK" ]; then
    ENFORCE_PROT="true"
else
    ENFORCE_PROT="false"
fi
info "auth_mode                  : ${AUTH_MODE}"
info "requires protection        : ${ENFORCE_PROT}"
info "accept_implicit            : ${ACCEPT_IMPLICIT}"
info "enrollment_ca              : ${ENROLLMENT_CA:-<empty>}"

# ── Step 2: bootstrap credentials + device key ────────────────────────────────
echo ""
echo "[2/9] Provisioning bootstrap CA + signer (registered as ValidationCA)..."
# shellcheck source=cmp-bootstrap-setup.sh
. "${SCRIPT_DIR}/cmp-bootstrap-setup.sh"
cmp_bootstrap_setup "${SERVER}" "${DMS_ID}" "${WORKDIR}" || fail "bootstrap setup failed"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORKDIR}/device.key" 2>/dev/null
ok "bootstrap CA ${BOOTSTRAP_CA_ID} + signer + device keys ready"

# ── Step 3: build the IR DER (openssl always emits pvno=2) ────────────────────
echo ""
echo "[3/9] Building IR DER (openssl points at a closed port — no transmission yet)..."
set +e
openssl cmp \
    -cmd ir \
    -server http://127.0.0.1:1 -path /nowhere \
    -cert "${WORKDIR}/signer.crt" -key "${WORKDIR}/signer.key" \
    -extracerts "${WORKDIR}/signer.crt" \
    -newkey "${WORKDIR}/device.key" -subject "/CN=${DEVICE_CN}" \
    -reqout "${WORKDIR}/ir-request-v2.der" \
    -certout "${WORKDIR}/discard.crt" \
    -msg_timeout 1 \
    >"${WORKDIR}/ir.stdout" 2>"${WORKDIR}/ir.stderr"
set -e
[ -s "${WORKDIR}/ir-request-v2.der" ] || fail "openssl did not write the IR DER — check ${WORKDIR}/ir.stderr"
info "IR DER (pvno=2, signed) : $(wc -c < "${WORKDIR}/ir-request-v2.der") bytes"

# ── Step 4: patch pvno=2 → 3 AND re-sign over the new header ─────────────────
#
# We must re-sign because openssl signed the original `SEQUENCE { header, body }`
# under pvno=2. Flipping the pvno byte invalidates that signature, and a DMS
# with auth_mode=CLIENT_CERTIFICATE rejects the bare patched DER. The
# python heredoc below:
#   1. Locates and patches the pvno byte (02 01 02 → 02 01 03).
#   2. Locates the Protection [0] BIT STRING TLV.
#   3. Rebuilds the protected payload SEQUENCE { patched_header, body }.
#   4. Signs it with signer.key (ECDSA-SHA256) via openssl dgst.
#   5. Replaces the old BIT STRING content with the new signature.
#   6. Writes the result to ir-request.der and prints the transactionID.
echo ""
echo "[4/9] Patching IR DER: pvno 2 → 3 + re-signing over the new header..."

TX_HEX=$(python3 <<PYEOF
import subprocess, sys

src = "${WORKDIR}/ir-request-v2.der"
dst = "${WORKDIR}/ir-request.der"
signer_key = "${WORKDIR}/signer.key"

with open(src, "rb") as f:
    data = bytearray(f.read())

def read_len(buf, off):
    n = buf[off]; off += 1
    if n < 128:
        return n, off
    nb = n & 0x7F
    return int.from_bytes(buf[off:off+nb], "big"), off + nb

def skip_tlv_header(buf, off):
    off += 1                         # skip tag
    _, off = read_len(buf, off)
    return off

# Find pvno offset: outer SEQUENCE → PKIHeader SEQUENCE → first INTEGER.
o = skip_tlv_header(data, 0)
if data[o] != 0x30:
    sys.exit(f"expected PKIHeader SEQUENCE at offset {o}, got {hex(data[o])}")
header_body_off = skip_tlv_header(data, o)
if data[header_body_off:header_body_off+3] != b"\x02\x01\x02":
    sys.exit(f"expected pvno=2 at offset {header_body_off}, got {bytes(data[header_body_off:header_body_off+3]).hex()}")
data[header_body_off+2] = 0x03

# Locate header TLV and body TLV at the outer SEQUENCE's top level.
outer_content_off = skip_tlv_header(data, 0)
# Header
h_tag_off = outer_content_off
h_len, h_lhdr_end = read_len(data, h_tag_off + 1)
h_content_off = h_lhdr_end
h_end = h_content_off + h_len
header_full = bytes(data[h_tag_off:h_end])
# Body (next TLV)
b_tag_off = h_end
b_len, b_lhdr_end = read_len(data, b_tag_off + 1)
b_content_off = b_lhdr_end
b_end = b_content_off + b_len
body_full = bytes(data[b_tag_off:b_end])

# Locate Protection [0] EXPLICIT BIT STRING.
prot_tag_off = b_end
if prot_tag_off >= len(data) or data[prot_tag_off] != 0xA0:
    sys.exit("no Protection [0] field present — IR is unsigned; nothing to re-sign")
prot_len, prot_lhdr_end = read_len(data, prot_tag_off + 1)
prot_content_off = prot_lhdr_end
prot_end = prot_content_off + prot_len

# The Protection [0] content is itself a BIT STRING TLV.
if data[prot_content_off] != 0x03:
    sys.exit(f"Protection inner is not a BIT STRING (tag={hex(data[prot_content_off])})")
bs_len, bs_lhdr_end = read_len(data, prot_content_off + 1)
bs_content_off = bs_lhdr_end
bs_end = bs_content_off + bs_len
# bs_content is unused_bits || sig_bytes. For ECDSA-DER signatures, unused_bits is 0.
old_sig_with_unused = bytes(data[bs_content_off:bs_end])
if not old_sig_with_unused or old_sig_with_unused[0] != 0:
    sys.exit(f"expected 0 unused-bits in protection BIT STRING, got {old_sig_with_unused[0] if old_sig_with_unused else 'empty'}")

# Build the protected payload: SEQUENCE { patched_header, body }.
payload = header_full + body_full
def der_seq(content):
    n = len(content)
    if n < 128:
        return bytes([0x30, n]) + content
    elif n < 256:
        return bytes([0x30, 0x81, n]) + content
    elif n < 65536:
        return bytes([0x30, 0x82, n >> 8, n & 0xFF]) + content
    raise ValueError("payload too large")
protected_seq = der_seq(payload)

# Sign with openssl dgst — produces DER-encoded ECDSA(r,s).
result = subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", signer_key],
    input=protected_seq, capture_output=True, check=True,
)
new_sig = result.stdout
# New BIT STRING content: unused-bits (0x00) + new signature.
new_bs_content = b"\x00" + new_sig

# Rebuild Protection [0]:
#   inner BIT STRING TLV
def der_bitstring(content):
    n = len(content)
    if n < 128:
        return bytes([0x03, n]) + content
    elif n < 256:
        return bytes([0x03, 0x81, n]) + content
    elif n < 65536:
        return bytes([0x03, 0x82, n >> 8, n & 0xFF]) + content
    raise ValueError("BIT STRING too large")
new_bs_tlv = der_bitstring(new_bs_content)
def der_context_explicit(tag_num, content):
    n = len(content)
    tag = 0xA0 | tag_num
    if n < 128:
        return bytes([tag, n]) + content
    elif n < 256:
        return bytes([tag, 0x81, n]) + content
    elif n < 65536:
        return bytes([tag, 0x82, n >> 8, n & 0xFF]) + content
    raise ValueError("[N] EXPLICIT content too large")
new_prot_tlv = der_context_explicit(0, new_bs_tlv)

# Anything after the old Protection (typically extraCerts [1]) we keep intact.
after_protection = bytes(data[prot_end:])

# Rebuild the outer SEQUENCE with patched header + body + new protection + tail.
new_inner = header_full + body_full + new_prot_tlv + after_protection
new_outer = der_seq(new_inner)

# Sanity: the only thing that should differ in length is the protection TLV,
# but ECDSA-DER signatures are usually the same length (70-72 bytes); a
# 1-2-byte difference in outer length is fine because der_seq picks the
# right length-form automatically.

# Extract the transactionID from the header for the rest of the script.
# transactionID is [4] EXPLICIT OCTET STRING (16 bytes) = a4 12 04 10 <16>.
tx_marker = bytes([0xA4, 0x12, 0x04, 0x10])
hi = bytes(header_full).find(tx_marker)
if hi < 0:
    sys.exit("transactionID marker not found in header")
tx_id = bytes(header_full[hi+4:hi+20])

with open(dst, "wb") as f:
    f.write(new_outer)
print(tx_id.hex())
PYEOF
)
[ -n "${TX_HEX}" ] || fail "DER patch/re-sign failed — see python output above"
ok "IR patched + re-signed — transactionID ${TX_HEX} ($(wc -c < "${WORKDIR}/ir-request.der") bytes, pvno=3)"

PVNO_WIRE=$(cmp_pvno "${WORKDIR}/ir-request.der")
[ "${PVNO_WIRE}" = "3" ] || fail "wire-level pvno is ${PVNO_WIRE}, expected 3"
info "wire-level pvno confirmed = 3 (cmp2021)"

# ── Step 5: POST the IR, discard the response (drop simulation) ───────────────
echo ""
echo "[5/9] Sending pvno=3 IR via curl, discarding response (simulated drop)..."
HTTP_CODE=$(curl -sS -o "${WORKDIR}/ir-response.der" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/pkixcmp" \
    --data-binary "@${WORKDIR}/ir-request.der" \
    --max-time 10 \
    "${SERVER}${CMP_PATH}" || echo "000")
info "curl HTTP status: ${HTTP_CODE} ($(wc -c < "${WORKDIR}/ir-response.der") bytes)"
[ "${HTTP_CODE}" = "200" ] || fail "server did not accept the pvno=3 IR (status ${HTTP_CODE})"

# CMP-level errors still return HTTP 200 with an error PKIMessage body, so
# we MUST inspect the body tag — relying on HTTP status alone hides server
# rejections of the (mis-signed or otherwise malformed) IR.
RESP_TAG=$(cmp_body_tag "${WORKDIR}/ir-response.der")
RESP_PVNO=$(cmp_pvno "${WORKDIR}/ir-response.der")
case "${RESP_TAG}" in
    1)  # ip
        ok "server returned ip body (tag=1) with pvno=${RESP_PVNO} — IR was accepted"
        ;;
    23) # error
        REASON=$(cmp_error_reason "${WORKDIR}/ir-response.der")
        fail "server REJECTED the pvno=3 IR with a CMP error (pvno=${RESP_PVNO}): ${REASON}"
        ;;
    *)
        fail "unexpected body tag ${RESP_TAG} on IR response — expected 1 (ip) or 23 (error)"
        ;;
esac
[ "${RESP_PVNO}" = "3" ] || fail "ip response pvno is ${RESP_PVNO}, expected 3"

# ── Step 6: confirm transaction state via the management API ─────────────────
echo ""
echo "[6/9] Verifying transaction state via /dms/{id}/cmp/transactions..."
fetch_state() {
    local filter="filter=transaction_id%5Bequal%5D${1}"
    curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?${filter}" \
        | jq -r '.list[0].state // empty'
}
# Storage may need a moment to flush after the inline IR response.
for attempt in 1 2 3 4 5; do
    sleep 1
    STATE=$(fetch_state "${TX_HEX}")
    [ -n "${STATE}" ] && break
    note "row not yet visible (attempt ${attempt}/5)"
done

if [ -z "${STATE}" ]; then
    note "txID lookup failed — listing recent rows by CN to diagnose"
    curl -sf "${SERVER}/api/dmsmanager/v1/dms/${DMS_ID}/cmp/transactions?filter=subject_common_name%5Bequal%5D${DEVICE_CN}" \
        | jq '.list[] | {transaction_id, state, subject_common_name, created_at}' \
        || true
    fail "no transaction row found for txID ${TX_HEX} (CN=${DEVICE_CN})"
fi
case "${STATE}" in
    ISSUED) ok "state=ISSUED — ready for pvno=3 pollReq" ;;
    *) fail "unexpected state '${STATE}' — expected ISSUED" ;;
esac

# ── Step 7: build + send a pvno=3 pollReq (inline, no helper used) ────────────
#
# We build pollReq directly in python so we don't depend on cmp_pollreq.py
# supporting --pvno. The structure is: PKIMessage = SEQUENCE { header, body }
# where header carries pvno=3 + transactionID + senderNonce, and body is
# [25] EXPLICIT { SEQUENCE OF SEQUENCE { certReqId } }. If the DMS enforces
# protection, we also attach a signed Protection [0] BIT STRING + extraCerts.
echo ""
echo "[7/9] Sending pvno=3 pollReq with the captured transactionID..."

POLLREP_DER="${WORKDIR}/pollrep.der"
SIGN_FLAG=""
if [ "${ENFORCE_PROT}" = "true" ]; then
    SIGN_FLAG="yes"
    note "DMS enforces request protection — signing the pollReq"
else
    note "DMS does NOT enforce request protection — unsigned pollReq"
fi

python3 <<PYEOF || fail "failed to build/send pollReq"
import os, secrets, subprocess, sys, urllib.request

server = "${SERVER}"
path   = "${CMP_PATH}"
tx_id  = bytes.fromhex("${TX_HEX}")
sign   = "${SIGN_FLAG}" == "yes"
signer_cert = "${WORKDIR}/signer.crt"
signer_key  = "${WORKDIR}/signer.key"
out_path    = "${POLLREP_DER}"

# ── tiny DER builder ─────────────────────────────────────────────────────
def lenfield(n):
    if n < 128: return bytes([n])
    if n < 256: return bytes([0x81, n])
    if n < 65536: return bytes([0x82, n >> 8, n & 0xFF])
    raise ValueError("len too large")
def tlv(tag, body): return bytes([tag]) + lenfield(len(body)) + body
def integer(n):
    if n == 0: return tlv(0x02, b"\\x00")
    o = []
    while n:
        o.insert(0, n & 0xFF); n >>= 8
    if o[0] & 0x80: o.insert(0, 0)
    return tlv(0x02, bytes(o))
def sequence(*items): return tlv(0x30, b"".join(items))
def octet_string(v): return tlv(0x04, v)
def bit_string(v):   return tlv(0x03, b"\\x00" + v)
def context_explicit(n, c): return tlv(0xA0 | n, c)
def oid_der(dotted):
    p = [int(x) for x in dotted.split(".")]
    enc = bytes([40*p[0] + p[1]])
    for v in p[2:]:
        if v == 0: enc += b"\\x00"; continue
        b = []
        while v:
            b.insert(0, v & 0x7F); v >>= 7
        for i in range(len(b)-1): b[i] |= 0x80
        enc += bytes(b)
    return tlv(0x06, enc)
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

# Build pvno=3 header.
pvno = integer(3)
empty_name = context_explicit(4, sequence())
tx_field = context_explicit(4, octet_string(tx_id))
nonce_field = context_explicit(5, octet_string(secrets.token_bytes(16)))
hdr_fields = [pvno, empty_name, empty_name]
if sign:
    hdr_fields.append(context_explicit(1, sequence(oid_der(OID_ECDSA_SHA256))))
hdr_fields.extend([tx_field, nonce_field])
header = sequence(*hdr_fields)

# Body: [25] EXPLICIT { SEQUENCE OF SEQUENCE { certReqId } }
inner_entry = sequence(integer(0))
body = context_explicit(25, sequence(inner_entry))

if sign:
    payload = sequence(header, body)
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", signer_key],
        input=payload, capture_output=True, check=True,
    ).stdout
    protection = context_explicit(0, bit_string(sig))
    cert_der = subprocess.run(
        ["openssl", "x509", "-in", signer_cert, "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    extra_certs = tlv(0xA1, cert_der)  # [1] IMPLICIT SEQUENCE OF
    msg = sequence(header, body, protection, extra_certs)
else:
    msg = sequence(header, body)

req = urllib.request.Request(
    server.rstrip("/") + path,
    data=msg,
    headers={"Content-Type": "application/pkixcmp"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as resp:
    body = resp.read()
with open(out_path, "wb") as f:
    f.write(body)
print(f"pollRep saved : {out_path} ({len(body)} bytes)")
PYEOF

POLL_TAG=$(cmp_body_tag "${POLLREP_DER}")
POLL_PVNO=$(cmp_pvno "${POLLREP_DER}")
case "${POLL_TAG}" in
    1|3)
        ok "pollRep body tag=${POLL_TAG} (cert delivered), pvno=${POLL_PVNO}"
        ;;
    23)
        REASON=$(cmp_error_reason "${POLLREP_DER}")
        fail "pollReq REJECTED (pvno=${POLL_PVNO}): ${REASON}"
        ;;
    26)
        fail "server still PENDING (pollRep checkAfter) — unexpected in sync mode"
        ;;
    *)
        fail "unexpected pollRep body tag ${POLL_TAG}"
        ;;
esac
[ "${POLL_PVNO}" = "3" ] || fail "pollRep pvno is ${POLL_PVNO}, expected 3"

# ── Step 8: pvno=3 certConf (explicit confirm only) ──────────────────────────
echo ""
if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    echo "[8/9] DMS uses implicit confirmation — server already CONFIRMED the row on pollReq delivery. Skipping certConf."
else
    echo "[8/9] DMS requires explicit confirmation — sending pvno=3 certConf..."
    PKICONF_DER="${WORKDIR}/pkiconf.der"

python3 <<PYEOF || fail "failed to build/send certConf"
import hashlib, secrets, subprocess, urllib.request

server = "${SERVER}"
path   = "${CMP_PATH}"
pollrep_path = "${POLLREP_DER}"
sign   = "${SIGN_FLAG}" == "yes"
signer_cert = "${WORKDIR}/signer.crt"
signer_key  = "${WORKDIR}/signer.key"
out_path    = "${PKICONF_DER}"

# ── tiny DER builder (duplicated from step 7 — keeping each heredoc self-contained) ──
def lenfield(n):
    if n < 128: return bytes([n])
    if n < 256: return bytes([0x81, n])
    if n < 65536: return bytes([0x82, n >> 8, n & 0xFF])
    raise ValueError("len too large")
def tlv(tag, body): return bytes([tag]) + lenfield(len(body)) + body
def integer(n):
    if n == 0: return tlv(0x02, b"\\x00")
    o = []
    while n:
        o.insert(0, n & 0xFF); n >>= 8
    if o[0] & 0x80: o.insert(0, 0)
    return tlv(0x02, bytes(o))
def sequence(*items): return tlv(0x30, b"".join(items))
def octet_string(v): return tlv(0x04, v)
def bit_string(v):   return tlv(0x03, b"\\x00" + v)
def context_explicit(n, c): return tlv(0xA0 | n, c)
def oid_der(dotted):
    p = [int(x) for x in dotted.split(".")]
    enc = bytes([40*p[0] + p[1]])
    for v in p[2:]:
        if v == 0: enc += b"\\x00"; continue
        b = []
        while v:
            b.insert(0, v & 0x7F); v >>= 7
        for i in range(len(b)-1): b[i] |= 0x80
        enc += bytes(b)
    return tlv(0x06, enc)
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

# ── extract { transactionID, senderNonce, cert } from the pollrep ────────
with open(pollrep_path, "rb") as f:
    rep = f.read()

def read_len(buf, off):
    n = buf[off]
    if n < 128: return n, off + 1
    nb = n & 0x7F
    return int.from_bytes(buf[off+1:off+1+nb], "big"), off + 1 + nb

# Walk: outer SEQUENCE → header SEQUENCE → fields
o = 1; _, o = read_len(rep, o)              # past outer SEQUENCE tag+len
hdr_tag_off = o
hdr_len, o = read_len(rep, o + 1)
hdr_content_off = o
hdr_end = hdr_content_off + hdr_len

# Scan header for [4] tx_id and [5] senderNonce.
tx_id = None
sender_nonce = None
i = hdr_content_off
while i < hdr_end:
    tag = rep[i]
    ln, lstart = read_len(rep, i + 1)
    inner = rep[lstart:lstart+ln]
    if tag == 0xA4 and len(inner) > 2 and inner[0] == 0x04:
        ilen, istart = read_len(inner, 1)
        tx_id = inner[istart:istart+ilen]
    elif tag == 0xA5 and len(inner) > 2 and inner[0] == 0x04:
        ilen, istart = read_len(inner, 1)
        sender_nonce = inner[istart:istart+ilen]
    i = lstart + ln
if not tx_id or not sender_nonce:
    raise SystemExit("pollrep missing transactionID or senderNonce")

# Scan the body for the cert: the longest SEQUENCE that openssl x509 accepts.
# IMPORTANT: search only the body TLV (between header and protection/extraCerts)
# to avoid picking up CA certificates from extraCerts which are typically larger.
body_tag_off = hdr_end
body_len, body_content_off = read_len(rep, body_tag_off + 1)
body_end = body_content_off + body_len
body_region = rep[body_tag_off:body_end]

def candidate_certs(buf):
    out = []
    n = len(buf)
    i = 0
    while i < n - 1:
        if buf[i] == 0x30 and buf[i+1] & 0x80:
            nb = buf[i+1] & 0x7F
            if i + 2 + nb <= n:
                ln = int.from_bytes(buf[i+2:i+2+nb], "big")
                end = i + 2 + nb + ln
                if end <= n:
                    out.append((end - i, buf[i:end]))
        i += 1
    out.sort(reverse=True)
    return [b for _, b in out]

cert_der = None
for cand in candidate_certs(body_region):
    try:
        subprocess.run(["openssl", "x509", "-inform", "DER", "-noout"],
                       input=cand, capture_output=True, check=True)
        cert_der = cand
        break
    except subprocess.CalledProcessError:
        continue
if cert_der is None:
    raise SystemExit("could not find a Certificate in pollrep body — cannot certConf")

# ── build the pvno=3 certConf message ────────────────────────────────────
cert_hash = hashlib.sha256(cert_der).digest()
hash_alg = context_explicit(0, sequence(oid_der("2.16.840.1.101.3.4.2.1")))
cert_status = sequence(octet_string(cert_hash), integer(0), hash_alg)
body = context_explicit(24, sequence(cert_status))

pvno = integer(3)
empty_name = context_explicit(4, sequence())
tx_field = context_explicit(4, octet_string(tx_id))
new_nonce = context_explicit(5, octet_string(secrets.token_bytes(16)))
recip_nonce = context_explicit(6, octet_string(sender_nonce))
hdr_fields = [pvno, empty_name, empty_name]
if sign:
    hdr_fields.append(context_explicit(1, sequence(oid_der(OID_ECDSA_SHA256))))
hdr_fields.extend([tx_field, new_nonce, recip_nonce])
header = sequence(*hdr_fields)

if sign:
    payload = sequence(header, body)
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", signer_key],
        input=payload, capture_output=True, check=True,
    ).stdout
    protection = context_explicit(0, bit_string(sig))
    cert_signer = subprocess.run(
        ["openssl", "x509", "-in", signer_cert, "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    extra = tlv(0xA1, cert_signer)
    msg = sequence(header, body, protection, extra)
else:
    msg = sequence(header, body)

req = urllib.request.Request(
    server.rstrip("/") + path,
    data=msg,
    headers={"Content-Type": "application/pkixcmp"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as resp:
    body = resp.read()
with open(out_path, "wb") as f:
    f.write(body)
print(f"pkiConf saved : {out_path} ({len(body)} bytes)")
PYEOF

    PKI_TAG=$(cmp_body_tag "${PKICONF_DER}")
    PKI_PVNO=$(cmp_pvno "${PKICONF_DER}")
    case "${PKI_TAG}" in
        19) ok "server returned pkiConf (tag=19) with pvno=${PKI_PVNO}" ;;
        23)
            REASON=$(cmp_error_reason "${PKICONF_DER}")
            fail "certConf REJECTED (pvno=${PKI_PVNO}): ${REASON}"
            ;;
        *) fail "unexpected pkiConf body tag ${PKI_TAG}" ;;
    esac
    [ "${PKI_PVNO}" = "3" ] || fail "pkiConf pvno is ${PKI_PVNO}, expected 3"
fi

# ── Step 9: verify the row reached CONFIRMED ─────────────────────────────────
echo ""
echo "[9/9] Re-checking transaction state..."
sleep 1
STATE=$(fetch_state "${TX_HEX}")
case "${STATE}" in
    CONFIRMED) ok "state=CONFIRMED — pvno=3 enrollment complete" ;;
    ISSUED)    fail "state still ISSUED — certConf was not honoured" ;;
    "")        fail "transaction row vanished — was DeleteExpired racing?" ;;
    *)         fail "unexpected final state '${STATE}'" ;;
esac

echo ""
echo "========================================================================"
echo -e "${GREEN} CMP v3 DROP-AND-POLL SUCCEEDED${RESET}"
echo "========================================================================"
echo "  - IR built by openssl (pvno=2), patched to pvno=3, RE-SIGNED"
echo "  - server accepted the pvno=3 IR and persisted ISSUED row"
echo "  - pvno=3 pollReq redelivered the cert; response also pvno=3"
if [ "${ACCEPT_IMPLICIT}" = "true" ]; then
    echo "  - implicit confirmation: row reached CONFIRMED on pollReq delivery"
else
    echo "  - pvno=3 certConf accepted; pkiConf pvno=3; row reached CONFIRMED"
fi
echo ""
echo "  RFC 9810 §7 line 3754 satisfied: every response echoed the request's pvno."
echo ""
echo "  Files preserved in: ${WORKDIR}"
echo "    ir-request-v2.der   – openssl-built IR (pvno=2, original signature)"
echo "    ir-request.der      – patched + re-signed IR (pvno=3, what we sent)"
echo "    ir-response.der     – the IP response curl received and ignored"
echo "    pollrep.der         – the pvno=3 pollReq response (carries the cert)"
if [ "${ACCEPT_IMPLICIT}" != "true" ]; then
    echo "    pkiconf.der         – the pvno=3 pkiConf acknowledging certConf"
fi
echo "========================================================================"
