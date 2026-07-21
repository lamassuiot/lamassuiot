package cms

import "encoding/asn1"

// Cryptographic Message Syntax object identifiers (RFC 5652, RFC 5958,
// RFC 5480, RFC 5753, RFC 8017, RFC 9481). These are the exact OIDs the
// RFC 9483 §4.1.6 central-key-generation compliance validator checks, so they
// are pinned here as the single source of truth for both the CMS encoder and
// decoder rather than pulled from x509 internals (which does not expose them).
var (
	// oidSignedData / oidData are the CMS content types (RFC 5652 §3).
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// oidContentType / oidMessageDigest are the two mandatory CMS signed
	// attributes (RFC 5652 §11.1/§11.2).
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// oidKeyPackage is id-ct-KP-aKeyPackage (RFC 5958 §3): the eContentType of
	// a SignedData carrying an AsymmetricKeyPackage (e.g. a generated key).
	oidKeyPackage = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 78, 5}

	// Digest and signature algorithms.
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// oidRSAESOAEP / oidMGF1 are the RSAES-OAEP key-transport algorithm (RFC
	// 8017 §A.2.1 / RFC 4055 §4.1) and its mask-generation-function algorithm.
	// RFC 9481 requires RSAES-OAEP (not the legacy PKCS#1 v1.5 encryption
	// scheme, which is vulnerable to Bleichenbacher/ROBOT-style padding-oracle
	// attacks) for CMP central-key-generation key transport.
	oidRSAESOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// Content and key-wrap symmetric algorithms (RFC 9481).
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES256Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}

	// oidDHSinglePassStdDHSHA256 is dhSinglePass-stdDH-sha256kdf-scheme
	// (RFC 9481 / SEC1): the KARI key-encryption algorithm — ephemeral-static
	// ECDH with the ANSI-X9.63 KDF (SHA-256), wrapping the CEK with AES-256-wrap.
	oidDHSinglePassStdDHSHA256 = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
)

// OIDSignedData returns the id-signedData CMS content type (RFC 5652 §3): the
// content type of a SignedData, and the content type to pass to
// BuildEnvelopedData when the enveloped content is itself a SignedData.
func OIDSignedData() asn1.ObjectIdentifier { return cloneOID(oidSignedData) }

// OIDData returns the id-data CMS content type (RFC 5652 §3): the content type
// to pass to BuildEnvelopedData when enveloping arbitrary bytes (e.g. a bare
// certificate for CMP's encrCert proof-of-possession).
func OIDData() asn1.ObjectIdentifier { return cloneOID(oidData) }

// OIDKeyPackage returns id-ct-KP-aKeyPackage (RFC 5958 §3): the eContentType to
// pass to BuildSignedData when the encapsulated content is an
// AsymmetricKeyPackage produced by MarshalAsymmetricKeyPackage.
func OIDKeyPackage() asn1.ObjectIdentifier { return cloneOID(oidKeyPackage) }

// OIDSHA256WithRSA returns sha256WithRSAEncryption (RFC 8017): the RSA signature
// algorithm this package emits/verifies for the SHA-256 profile (RFC 9481).
func OIDSHA256WithRSA() asn1.ObjectIdentifier { return cloneOID(oidSHA256WithRSA) }

// OIDECDSAWithSHA256 returns ecdsa-with-SHA256 (RFC 5758): the ECDSA signature
// algorithm this package emits/verifies for the SHA-256 profile (RFC 9481).
func OIDECDSAWithSHA256() asn1.ObjectIdentifier { return cloneOID(oidECDSAWithSHA256) }

// cloneOID returns a copy so callers cannot mutate the package-level OIDs.
func cloneOID(oid asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	out := make(asn1.ObjectIdentifier, len(oid))
	copy(out, oid)
	return out
}

// containsOID reports whether target appears in oids.
func containsOID(oids []asn1.ObjectIdentifier, target asn1.ObjectIdentifier) bool {
	for _, oid := range oids {
		if oid.Equal(target) {
			return true
		}
	}
	return false
}
