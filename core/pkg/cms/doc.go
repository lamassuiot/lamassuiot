// Package cms implements the subset of the Cryptographic Message Syntax
// (RFC 5652) needed for RFC 9483 / RFC 9480 (CMP) central key generation and
// encrypted proof-of-possession: building and opening CMS SignedData and
// EnvelopedData structures.
//
// It is the single source of truth for the CMS wire format shared by the CMP
// server (which builds these structures to deliver a generated key or an
// encrypted certificate/nonce) and CMP clients (which open them). Because the
// encoder and decoder live together, the OIDs, ASN.1 SEQUENCE shapes, RFC 3394
// AES key wrap, and ANSI-X9.63 KDF cannot drift apart.
//
// The delivered central-key-generation blob (RFC 9483 §4.1.6) is an
// EnvelopedData whose encrypted content is a SignedData (signed by the KGA)
// wrapping an RFC 5958 AsymmetricKeyPackage:
//
//	EnvelopedData {
//	    recipientInfos       — how the content-encryption key (CEK) reaches the
//	                           recipient: ktri (RSA key transport) or kari
//	                           (ECDH key agreement)
//	    encryptedContentInfo — AES-256-CBC( SignedData ) under the CEK
//	}
//	SignedData {
//	    eContentType   id-ct-KP-aKeyPackage
//	    eContent       AsymmetricKeyPackage( OneAsymmetricKey(genKey) )
//	    signerInfos    signed by the KGA certificate
//	}
//
// Only RSA (key transport) and ECDSA (key agreement) recipient/signer keys are
// supported, with SHA-256 throughout, matching the RFC 9481 algorithm profile.
package cms
