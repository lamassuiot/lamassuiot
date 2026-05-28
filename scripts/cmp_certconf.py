#!/usr/bin/env python3
"""
Minimal CMP certConf client.

Builds an RFC 4210 §5.3.18 CertConfirmContent PKIMessage, POSTs it to a
Lamassu CMP endpoint, and reports the pkiConf response. Designed to be
called right after `cmp_pollreq.py` (or any other path that retrieves an
IP/CP response) when the DMS is configured for *explicit* confirmation —
i.e. `accept_implicit=false`. Without this round-trip the server keeps the
transaction in ISSUED state until the confirmation timeout elapses; the
CMP confirmation monitor then revokes the cert because nobody told the
server the EE accepted it.

Input
-----
- The IP/CP response from the prior pollReq (or the original IR), so we
  can extract:
    * the issued certificate DER (to compute certHash)
    * the server's senderNonce (echoed back as recipNonce per RFC 4210 §5.1.1)
    * the transactionID (also stored independently for verification)

Output
------
- pkiconf.der  — raw response from the server
- exit 0 when the server returns body tag 19 (pkiConf)
- exit non-zero with a parsed body tag name on any other outcome

Examples
--------

    ./cmp_certconf.py \
        --path /api/dmsmanager/.well-known/cmp/p/MyDMS \
        --pollrep pollrep.der \
        --signer-cert signer.crt --signer-key signer.key

    # Unprotected certConf (only when auth_mode is NO_AUTH or EXTERNAL_WEBHOOK)
    ./cmp_certconf.py \
        --path /api/dmsmanager/.well-known/cmp/p/MyDMS \
        --pollrep pollrep.der

The script intentionally re-uses the byte-level DER builder from
`cmp_pollreq.py` (imported when both live in the same directory) instead of
adding a `pyasn1`/`cryptography` dependency.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import urllib.error
import urllib.request

# Pull in the byte-level DER builder + helpers from the sibling script so we
# don't duplicate the ASN.1 plumbing. `cmp_pollreq.py` is a sibling file, so
# augment sys.path to find it even when this script is invoked by absolute path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmp_pollreq import (  # noqa: E402 — needs the sys.path tweak above.
    BODY_TAG_NAMES,
    bit_string,
    context_explicit,
    get_body_tag,
    integer,
    octet_string,
    oid,
    pem_cert_to_der,
    sequence,
    sign_protected_part,
    tlv,
)


# OID for SHA-256 (used as hashAlg in CertStatus). RFC 5754 §3.2.
OID_SHA256 = "2.16.840.1.101.3.4.2.1"

# Reuse the same protection algorithm as pollReq (ECDSA-SHA256). Keep in sync
# with cmp_pollreq.OID_ECDSA_SHA256.
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"


# ---------------------------------------------------------------------------
# Walk the IP/CP response to find: (1) issued cert DER, (2) senderNonce,
# (3) transactionID. The structure of an IP/CP response is:
#
#   PKIMessage ::= SEQUENCE {
#       header  PKIHeader,
#       body    PKIBody,
#       protection [0] BIT STRING OPTIONAL,
#       extraCerts [1] SEQUENCE OF CMPCertificate OPTIONAL
#   }
#
# Within the header we need:
#   * transactionID [4] EXPLICIT OCTET STRING
#   * senderNonce   [5] EXPLICIT OCTET STRING
#
# Within the body (IP=[1] / CP=[3]) the structure is:
#   CertRepMessage ::= SEQUENCE { caPubs OPTIONAL, response SEQUENCE OF CertResponse }
#   CertResponse ::= SEQUENCE { certReqId, status, certifiedKeyPair OPTIONAL, ... }
#   CertifiedKeyPair ::= SEQUENCE { certOrEncCert, ... }
#   CertOrEncCert ::= CHOICE { certificate [0] EXPLICIT Certificate, encryptedCert [1] ... }
#
# Rather than walk all of it, we scan for the longest top-level SEQUENCE that
# `openssl x509` accepts as a Certificate. That's robust against minor
# encoding variations in the response and avoids reimplementing the full ASN.1
# decoder here.
# ---------------------------------------------------------------------------

def parse_length(buf: bytes, off: int) -> tuple[int, int]:
    """Return (length, header_size) for a DER TLV starting at `off`."""
    first = buf[off + 1]
    if first < 128:
        return first, 2
    n = first & 0x7F
    length = int.from_bytes(buf[off + 2 : off + 2 + n], "big")
    return length, 2 + n


def find_explicit_octet_string(buf: bytes, off: int, tag_num: int) -> bytes | None:
    """Locate `[tag_num] EXPLICIT OCTET STRING` within a SEQUENCE content area.

    The header carries other fields that share the same outer tag — for
    example the `sender` GeneralName's `directoryName` CHOICE is `[4]`, so a
    naive "find the first 0xA4" walk returns the sender SEQUENCE instead of
    the transactionID OCTET STRING. We therefore walk every direct child of
    the SEQUENCE and only accept matches whose inner TLV is an OCTET STRING.
    """
    needle = 0xA0 | tag_num
    cur = off
    while cur < len(buf):
        if cur + 1 >= len(buf):
            return None
        tag = buf[cur]
        length, hdr = parse_length(buf, cur)
        next_cur = cur + hdr + length
        if tag == needle:
            inner_off = cur + hdr
            if inner_off < len(buf) and buf[inner_off] == 0x04:
                ilen, ihdr = parse_length(buf, inner_off)
                return buf[inner_off + ihdr : inner_off + ihdr + ilen]
            # Wrong inner type — keep scanning; another [tag_num] later in
            # the SEQUENCE may have the OCTET STRING we want.
        cur = next_cur
    return None


def extract_header_fields(resp_der: bytes) -> tuple[bytes, bytes]:
    """Return (transactionID, senderNonce) from an IP/CP response."""
    # Outer SEQUENCE
    if resp_der[0] != 0x30:
        raise ValueError("response is not a SEQUENCE")
    _, outer_hdr = parse_length(resp_der, 0)
    # First child = PKIHeader SEQUENCE
    if resp_der[outer_hdr] != 0x30:
        raise ValueError("first element is not the PKIHeader SEQUENCE")
    header_off = outer_hdr
    header_len, header_hdr = parse_length(resp_der, header_off)
    header_content_off = header_off + header_hdr
    header_content_end = header_content_off + header_len

    # Walk header children searching for [4] and [5] EXPLICIT OCTET STRING.
    header_content = resp_der[header_content_off:header_content_end]
    tx_id = find_explicit_octet_string(header_content, 0, 4)
    sender_nonce = find_explicit_octet_string(header_content, 0, 5)
    if tx_id is None:
        raise ValueError("transactionID not found in header")
    if sender_nonce is None:
        raise ValueError("senderNonce not found in header")
    return tx_id, sender_nonce


def _walk_children(buf: bytes, off: int, end: int):
    """Yield (tag_byte, content_offset, content_end) for each direct child
    inside a constructed TLV whose content area spans [off, end)."""
    cur = off
    while cur < end:
        if cur + 1 >= len(buf):
            return
        tag = buf[cur]
        try:
            length, hdr = parse_length(buf, cur)
        except IndexError:
            return
        content_start = cur + hdr
        content_end = content_start + length
        if content_end > end:
            return
        yield tag, content_start, content_end
        cur = content_end


def extract_certificate_der(resp_der: bytes) -> bytes:
    """Pull the issued device cert out of an IP/CP response.

    Structurally navigates:

        PKIMessage = SEQUENCE {
            header     PKIHeader,                          -- skip
            body       [1] CertRepMessage |                -- ip
                       [3] CertRepMessage,                 -- cp
            protection [0] BIT STRING OPTIONAL,            -- skip
            extraCerts [1] SEQUENCE OF Certificate OPT.    -- skip
        }
        CertRepMessage = SEQUENCE { caPubs?, response SEQUENCE OF CertResponse }
        CertResponse    = SEQUENCE { certReqId, status,
                                     certifiedKeyPair?, rspInfo? }
        CertifiedKeyPair = SEQUENCE { certOrEncCert, ... }
        CertOrEncCert    = certificate [0] EXPLICIT Certificate

    Returns the inner Certificate SEQUENCE bytes exactly as the server stored
    them in `cmp_transactions.cert_der`. A naive "find the biggest SEQUENCE"
    scan trips over the server's protection cert (carried in extraCerts and
    typically larger than the device cert), so we must respect the structure.
    """
    if not resp_der or resp_der[0] != 0x30:
        raise ValueError("response is not a SEQUENCE")
    outer_len, outer_hdr = parse_length(resp_der, 0)
    outer_end = outer_hdr + outer_len

    # Top-level: locate the body [1] (IP) or [3] (CP) child.
    body_child = None
    for tag, cstart, cend in _walk_children(resp_der, outer_hdr, outer_end):
        if tag in (0xA1, 0xA3):
            body_child = (cstart, cend)
            break
    if body_child is None:
        raise ValueError("no IP/CP body in response")
    body_cs, body_ce = body_child

    # body content is the CertRepMessage SEQUENCE.
    if resp_der[body_cs] != 0x30:
        raise ValueError("body is not a CertRepMessage SEQUENCE")
    crm_len, crm_hdr = parse_length(resp_der, body_cs)
    crm_cs = body_cs + crm_hdr
    crm_ce = crm_cs + crm_len

    # Inside CertRepMessage: caPubs [1] is optional, response is the first
    # universal SEQUENCE child.
    response_seq_of = None
    for tag, cs, ce in _walk_children(resp_der, crm_cs, crm_ce):
        if tag == 0x30:
            response_seq_of = (cs, ce)
            break
    if response_seq_of is None:
        raise ValueError("no response SEQUENCE OF in CertRepMessage")
    rs_cs, rs_ce = response_seq_of

    # response is SEQUENCE OF CertResponse — pick the first entry.
    cert_response = next(
        ((cs, ce) for tag, cs, ce in _walk_children(resp_der, rs_cs, rs_ce) if tag == 0x30),
        None,
    )
    if cert_response is None:
        raise ValueError("response SEQUENCE OF is empty")
    cr_cs, cr_ce = cert_response

    # CertResponse children: certReqId INTEGER, status SEQUENCE,
    # certifiedKeyPair SEQUENCE OPTIONAL, rspInfo OCTET STRING OPTIONAL.
    # The second SEQUENCE child is certifiedKeyPair (status is the first).
    sequence_children = [
        (cs, ce) for tag, cs, ce in _walk_children(resp_der, cr_cs, cr_ce) if tag == 0x30
    ]
    if len(sequence_children) < 2:
        raise ValueError("CertResponse has no certifiedKeyPair (status only)")
    ckp_cs, ckp_ce = sequence_children[1]

    # CertifiedKeyPair: first child is certOrEncCert = certificate [0] EXPLICIT.
    first_child = next(_walk_children(resp_der, ckp_cs, ckp_ce), None)
    if first_child is None:
        raise ValueError("certifiedKeyPair is empty")
    tag, ccs, _ = first_child
    if tag != 0xA0:
        raise ValueError(f"expected [0] EXPLICIT certificate, got tag 0x{tag:02x}")

    # Inside [0] EXPLICIT: the Certificate SEQUENCE.
    if resp_der[ccs] != 0x30:
        raise ValueError("[0] EXPLICIT does not wrap a Certificate SEQUENCE")
    cert_len, cert_hdr = parse_length(resp_der, ccs)
    cert_total = cert_hdr + cert_len
    cert_bytes = resp_der[ccs : ccs + cert_total]

    # Trust-but-verify: confirm openssl can parse what we extracted.
    if not _is_valid_certificate(cert_bytes):
        raise ValueError("extracted bytes are not a valid X.509 certificate")
    return cert_bytes


def _is_valid_certificate(der: bytes) -> bool:
    """Trial-parse `der` with `openssl x509`; quick, no extra deps."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout"],
            input=der,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# certConf builder
# ---------------------------------------------------------------------------

def build_certconf_header(tx_id: bytes, recip_nonce: bytes, signed: bool) -> bytes:
    """PKIHeader for a certConf — RFC 4210 §5.1.

    Sender / recipient are empty DirectoryNames (same as the pollReq script).
    transactionID echoes the IR. recipNonce echoes the server's last
    senderNonce (the one carried by the pollReq response). senderNonce is a
    fresh random 16 bytes — the server has no further response that consults
    it, but encoders/decoders expect the field.
    """
    import secrets

    pvno = integer(2)
    empty_name = context_explicit(4, sequence())
    tx_field = context_explicit(4, octet_string(tx_id))
    new_nonce = secrets.token_bytes(16)
    sender_nonce_field = context_explicit(5, octet_string(new_nonce))
    recip_nonce_field = context_explicit(6, octet_string(recip_nonce))

    fields = [pvno, empty_name, empty_name]
    if signed:
        alg_id = sequence(oid(OID_ECDSA_SHA256))
        fields.append(context_explicit(1, alg_id))
    fields.extend([tx_field, sender_nonce_field, recip_nonce_field])
    return sequence(*fields)


def build_certconf_body(cert_der: bytes, cert_req_id: int) -> bytes:
    """PKIBody [24] EXPLICIT CertConfirmContent.

    CertConfirmContent ::= SEQUENCE OF CertStatus
    CertStatus         ::= SEQUENCE { certHash OCTET STRING,
                                      certReqId INTEGER,
                                      statusInfo OPTIONAL,
                                      hashAlg [0] OPTIONAL }

    We send hashAlg = SHA-256 explicitly so the server doesn't have to guess
    (the Lamassu controller defaults to SHA-256 when hashAlg is absent, but
    being explicit is safer for cross-implementation testing).
    """
    cert_hash = hashlib.sha256(cert_der).digest()
    hash_alg = context_explicit(0, sequence(oid(OID_SHA256)))
    cert_status = sequence(
        octet_string(cert_hash),
        integer(cert_req_id),
        hash_alg,
    )
    seq_of = sequence(cert_status)
    return context_explicit(24, seq_of)


def build_certconf_message(
    tx_id: bytes,
    recip_nonce: bytes,
    cert_der: bytes,
    cert_req_id: int,
    signer_cert_pem: str | None,
    signer_key_pem: str | None,
) -> bytes:
    """Assemble the full certConf PKIMessage DER."""
    signed = bool(signer_key_pem)
    header = build_certconf_header(tx_id, recip_nonce, signed=signed)
    body = build_certconf_body(cert_der, cert_req_id)

    if not signed:
        return sequence(header, body)

    signer_cert_der = pem_cert_to_der(signer_cert_pem)
    sig_der = sign_protected_part(signer_key_pem, header, body)

    protection = context_explicit(0, bit_string(sig_der))
    extra_certs = tlv(0xA1, signer_cert_der)
    return sequence(header, body, protection, extra_certs)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Send a CMP certConf to confirm a previously delivered cert")
    p.add_argument("--server", default="http://localhost:8080", help="server base URL")
    p.add_argument("--path", required=True,
                   help="CMP endpoint path, e.g. /api/dmsmanager/.well-known/cmp/p/MyDMS")
    p.add_argument("--pollrep", required=True,
                   help="path to the IP/CP response DER carrying the cert + senderNonce we must echo")
    p.add_argument("--cert-req-id", type=int, default=0,
                   help="certReqId echoed in CertStatus (default 0, must match the IR/pollReq)")
    p.add_argument("--signer-cert",
                   help="PEM cert used in extraCerts (required when DMS enforces protection)")
    p.add_argument("--signer-key",
                   help="PEM private key matching --signer-cert (for signing)")
    p.add_argument("--out", default="pkiconf.der", help="where to save the raw server response")
    args = p.parse_args()

    if bool(args.signer_cert) != bool(args.signer_key):
        print("--signer-cert and --signer-key must be used together", file=sys.stderr)
        return 2

    with open(args.pollrep, "rb") as f:
        pollrep = f.read()

    tx_id, sender_nonce = extract_header_fields(pollrep)
    cert_der = extract_certificate_der(pollrep)

    print(f"transactionID : {tx_id.hex()}")
    print(f"recipNonce    : {sender_nonce.hex()}  (server's senderNonce from pollrep)")
    print(f"cert DER      : {len(cert_der)} bytes")
    print(f"certHash      : {hashlib.sha256(cert_der).hexdigest()}")
    print(f"signed        : {bool(args.signer_key)}")

    der = build_certconf_message(
        tx_id, sender_nonce, cert_der, args.cert_req_id,
        args.signer_cert, args.signer_key,
    )
    print(f"certConf DER  : {len(der)} bytes")

    url = args.server.rstrip("/") + args.path
    req = urllib.request.Request(
        url, data=der, headers={"Content-Type": "application/pkixcmp"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            body = resp.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()

    print(f"HTTP status   : {status}")
    print(f"Response size : {len(body)} bytes")
    with open(args.out, "wb") as f:
        f.write(body)
    print(f"Saved to      : {args.out}")

    if status == 200 and body:
        try:
            body_tag = get_body_tag(body)
            name = BODY_TAG_NAMES.get(body_tag, f"unknown({body_tag})")
            print(f"Body tag      : {body_tag} = {name}")
            if body_tag == 19:
                return 0
            return 1
        except (AssertionError, ValueError) as exc:
            print(f"could not parse response body tag: {exc}", file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
