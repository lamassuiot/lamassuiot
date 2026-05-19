#!/usr/bin/env python3
"""
Minimal CMP pollReq client.

Builds a (optionally signed) RFC 4210 §5.3.22 PollReqContent PKIMessage,
POSTs it to a Lamassu CMP endpoint, and dumps the response. Used to test
the lost-response / disconnect-recovery scenario: an EE sent an IR earlier
(possibly without receiving the cert because the connection dropped), and
now wants to retrieve the issued certificate using the same transactionID.

We avoid the `cryptography` and `pyasn1` Python deps:
  - ASN.1 DER is constructed byte-by-byte (CMP is structurally simple).
  - ECDSA signing is delegated to `openssl dgst`, which is already
    required for the surrounding test scripts.

Examples
--------

# Send an unprotected pollReq (only works when DMS has enforce_request_protection=false)
./cmp_pollreq.py \
    --path /api/dmsmanager/.well-known/cmp/p/MyDMS \
    --tx-id 8591e6c360f6c5f24d1c9ec8e6dc0a8e

# Send a signed pollReq matching the protection used by the original IR
./cmp_pollreq.py \
    --path /api/dmsmanager/.well-known/cmp/p/MyDMS \
    --extract-from ir-request.der \
    --signer-cert signer.crt --signer-key signer.key
"""
import argparse
import secrets
import subprocess
import sys
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# Tiny DER builder — enough for what CMP needs.
# ---------------------------------------------------------------------------

def _der_length(n: int) -> bytes:
    """ASN.1 DER length encoding (definite, short or long form)."""
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    if n < 65536:
        return bytes([0x82, n >> 8, n & 0xFF])
    if n < 16777216:
        return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError(f"length {n} too large")


def tlv(tag: int, body: bytes) -> bytes:
    """Generic TLV: 1-byte tag, definite length, body."""
    return bytes([tag]) + _der_length(len(body)) + body


def integer(n: int) -> bytes:
    """ASN.1 INTEGER, minimally encoded with the sign bit guard."""
    if n == 0:
        return tlv(0x02, b"\x00")
    octets = []
    while n:
        octets.insert(0, n & 0xFF)
        n >>= 8
    if octets[0] & 0x80:
        # Prepend 0x00 so the value is interpreted as positive.
        octets.insert(0, 0x00)
    return tlv(0x02, bytes(octets))


def sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def octet_string(value: bytes) -> bytes:
    return tlv(0x04, value)


def bit_string(value: bytes) -> bytes:
    # The first content byte counts unused trailing bits. For whole-byte
    # data (signatures, keys, etc.) it is always 0.
    return tlv(0x03, b"\x00" + value)


def context_explicit(tag_num: int, content: bytes) -> bytes:
    """[tag_num] EXPLICIT — context-specific, constructed, wraps content."""
    return tlv(0xA0 | tag_num, content)


def oid(dotted: str) -> bytes:
    """ASN.1 OBJECT IDENTIFIER encoding from a dotted-decimal string."""
    parts = [int(x) for x in dotted.split(".")]
    encoded = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            encoded += b"\x00"
        else:
            buf = []
            while p:
                buf.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(buf) - 1):
                buf[i] |= 0x80
            encoded += bytes(buf)
    return tlv(0x06, encoded)


# ---------------------------------------------------------------------------
# CMP message construction
# ---------------------------------------------------------------------------

# OIDs used in protection algorithms.
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

# Body CHOICE tag numbers (RFC 4210 §5.1.2).
BODY_TAG_NAMES = {
    1: "ip (initialization response)",
    3: "cp (certificate response)",
    8: "kup (key update response)",
    12: "rp (revocation response)",
    19: "pkiConf",
    23: "error",
    26: "pollRep (still waiting)",
}


def build_pkiheader(tx_id: bytes, signed: bool) -> bytes:
    """Build PKIHeader with the minimum fields the controller expects.

    sender / recipient are empty DirectoryNames (GeneralName CHOICE [4]).
    transactionID and senderNonce are mandatory for the controller's parser.
    protectionAlg [1] EXPLICIT is included only when we will sign the message
    so verifyRequestProtection() doesn't reject us with "wrong alg".
    """
    pvno = integer(2)
    # GeneralName CHOICE [4] directoryName — empty RDNSequence is SEQUENCE {}
    empty_name = context_explicit(4, sequence())

    tx_field = context_explicit(4, octet_string(tx_id))
    nonce = secrets.token_bytes(16)
    nonce_field = context_explicit(5, octet_string(nonce))

    fields = [pvno, empty_name, empty_name]

    if signed:
        # protectionAlg [1] EXPLICIT AlgorithmIdentifier{ ecdsa-with-SHA256 }
        alg_id = sequence(oid(OID_ECDSA_SHA256))
        fields.append(context_explicit(1, alg_id))

    fields.extend([tx_field, nonce_field])
    return sequence(*fields)


def build_pollreq_body(cert_req_id: int) -> bytes:
    """PKIBody [25] EXPLICIT PollReqContent.

    PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER, … }
    With Lamassu's controller, body.Bytes is unwrapped to the SEQUENCE OF
    TLV — i.e. [25] EXPLICIT wraps the SEQUENCE OF.
    """
    one_entry = sequence(integer(cert_req_id))
    seq_of = sequence(one_entry)
    return context_explicit(25, seq_of)


def sign_protected_part(signer_key: str, header: bytes, body: bytes) -> bytes:
    """Sign SEQUENCE{header, body} with the EE's ECDSA key via openssl(1).

    Returns the DER-encoded ECDSA signature (the format CMP uses inside the
    Protection BIT STRING and that Lamassu's verifyRequestProtection expects).
    """
    protected_part = sequence(header, body)
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", signer_key],
        input=protected_part,
        capture_output=True,
        check=True,
    )
    return result.stdout


def pem_cert_to_der(pem_path: str) -> bytes:
    """Convert a PEM cert to DER via openssl x509."""
    result = subprocess.run(
        ["openssl", "x509", "-in", pem_path, "-outform", "DER"],
        capture_output=True,
        check=True,
    )
    return result.stdout


def build_pollreq_message(
    tx_id: bytes,
    cert_req_id: int,
    signer_cert_pem: str | None,
    signer_key_pem: str | None,
) -> bytes:
    """Assemble the complete PKIMessage DER, signed if a key is provided."""
    signed = bool(signer_key_pem)
    header = build_pkiheader(tx_id, signed=signed)
    body = build_pollreq_body(cert_req_id)

    if not signed:
        return sequence(header, body)

    cert_der = pem_cert_to_der(signer_cert_pem)
    sig_der = sign_protected_part(signer_key_pem, header, body)

    # Protection [0] EXPLICIT BIT STRING
    protection = context_explicit(0, bit_string(sig_der))

    # extraCerts [1] IMPLICIT SEQUENCE OF CMPCertificate
    # [1] IMPLICIT replaces the SEQUENCE OF tag, so the content is just the
    # concatenated Certificate TLVs (one cert here).
    extra_certs = tlv(0xA1, cert_der)

    return sequence(header, body, protection, extra_certs)


# ---------------------------------------------------------------------------
# Helpers around the IR capture file
# ---------------------------------------------------------------------------

def extract_tx_id(reqout_der_path: str) -> bytes:
    """Pull the 16-byte transactionID from an IR DER captured with -reqout.

    transactionID is encoded as `[4] EXPLICIT OCTET STRING (16 bytes)`, which
    on the wire is the unique pattern A4 12 04 10 <16 bytes>. The IR header
    contains no other [4] EXPLICIT OCTET STRING of length 16, so the search
    is unambiguous in practice.
    """
    with open(reqout_der_path, "rb") as f:
        data = f.read()
    needle = bytes([0xA4, 0x12, 0x04, 0x10])
    idx = data.find(needle)
    if idx == -1:
        raise ValueError(
            f"could not locate transactionID in {reqout_der_path} — "
            "is this a valid CMP request DER?"
        )
    return data[idx + 4 : idx + 4 + 16]


# ---------------------------------------------------------------------------
# Response inspection
# ---------------------------------------------------------------------------

def get_body_tag(resp_der: bytes) -> int:
    """Return the PKIBody CHOICE tag number from a CMP response DER.

    We walk: outer SEQUENCE → first child = PKIHeader SEQUENCE → second child
    = the [N] body tag. Tag class bits are stripped to get the raw tag number.
    """
    if not resp_der or resp_der[0] != 0x30:
        raise ValueError("response is not a SEQUENCE")
    # Outer SEQUENCE length parsing
    length_byte = resp_der[1]
    if length_byte < 128:
        cursor = 2
    else:
        cursor = 2 + (length_byte & 0x7F)
    # PKIHeader SEQUENCE
    assert resp_der[cursor] == 0x30, "first element must be the PKIHeader SEQUENCE"
    h_len_byte = resp_der[cursor + 1]
    if h_len_byte < 128:
        header_total = 2 + h_len_byte
    else:
        ll = h_len_byte & 0x7F
        header_total = 2 + ll + int.from_bytes(
            resp_der[cursor + 2 : cursor + 2 + ll], "big"
        )
    body_start = cursor + header_total
    body_tag_byte = resp_der[body_start]
    # Strip class (top 2 bits) + constructed (bit 5) — keep tag number (low 5 bits).
    return body_tag_byte & 0x1F


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Send a CMP pollReq to retrieve a stored cert")
    p.add_argument("--server", default="http://localhost:8080", help="server base URL")
    p.add_argument("--path", required=True,
                   help="CMP endpoint path, e.g. /api/dmsmanager/.well-known/cmp/p/MyDMS")
    p.add_argument("--tx-id", help="hex-encoded 16-byte transactionID")
    p.add_argument("--extract-from",
                   help="path to a CMP request DER (-reqout output) to pull the txID from")
    p.add_argument("--cert-req-id", type=int, default=0,
                   help="certReqId echoed in the pollReq (default 0, matches openssl)")
    p.add_argument("--signer-cert",
                   help="PEM cert used in extraCerts (required when DMS enforces protection)")
    p.add_argument("--signer-key",
                   help="PEM private key matching --signer-cert (for signing)")
    p.add_argument("--out", default="pollrep.der", help="where to save the raw server response")
    args = p.parse_args()

    if args.tx_id and args.extract_from:
        print("--tx-id and --extract-from are mutually exclusive", file=sys.stderr)
        return 2
    if args.tx_id:
        tx_id = bytes.fromhex(args.tx_id)
    elif args.extract_from:
        tx_id = extract_tx_id(args.extract_from)
    else:
        print("either --tx-id or --extract-from is required", file=sys.stderr)
        return 2
    if len(tx_id) != 16:
        print(f"transactionID must be 16 bytes, got {len(tx_id)}", file=sys.stderr)
        return 2

    if bool(args.signer_cert) != bool(args.signer_key):
        print("--signer-cert and --signer-key must be used together", file=sys.stderr)
        return 2

    print(f"transactionID : {tx_id.hex()}")
    print(f"certReqId     : {args.cert_req_id}")
    print(f"signed        : {bool(args.signer_key)}")

    der = build_pollreq_message(tx_id, args.cert_req_id, args.signer_cert, args.signer_key)
    print(f"pollReq DER   : {len(der)} bytes")

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
            if body_tag in (1, 3):
                print("→ cert delivered. Inspect with:")
                print(f"   openssl asn1parse -inform DER -in {args.out}")
            elif body_tag == 23:
                print("→ server returned a CMP error PKIMessage")
            elif body_tag == 26:
                print("→ server says still PENDING — try again later")
            return 0
        except (AssertionError, ValueError) as exc:
            print(f"could not parse response body tag: {exc}", file=sys.stderr)
            return 1
    return 1 if status != 200 else 0


if __name__ == "__main__":
    sys.exit(main())
