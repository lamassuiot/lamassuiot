package cmp

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type OldCertID struct {
	IssuerNameDER []byte
	SerialNumber  *big.Int
}

func normalizeSequenceDER(der []byte, label string) ([]byte, error) {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err == nil && rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
		return rv.FullBytes, nil
	}

	wrapped, err := WrapSequenceDER(der, label)
	if err != nil {
		return nil, err
	}

	var wrappedRV asn1.RawValue
	if _, err := asn1.Unmarshal(wrapped, &wrappedRV); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return wrappedRV.FullBytes, nil
}

func WrapSequenceDER(content []byte, label string) ([]byte, error) {
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		return nil, fmt.Errorf("rewrap %s: %w", label, err)
	}
	return der, nil
}

// CMP PKIBody CHOICE tag numbers (RFC 4210 §5.1.2 / RFC 9480).
const (
	BodyTagIR       = 0  // ir  – Initialization Request
	BodyTagIP       = 1  // ip  – Initialization Response
	BodyTagCR       = 2  // cr  – Certificate Request
	BodyTagCP       = 3  // cp  – Certificate Response
	BodyTagP10CR    = 4  // p10cr – PKCS#10 Certification Request (RFC 9483 §4.1.4)
	BodyTagPopDecc  = 5  // popdecc – POPO Challenge (RFC 4210bis §5.2.8.3)
	BodyTagPopDecr  = 6  // popdecr – POPO Decryption Response (RFC 4210bis §5.2.8.3)
	BodyTagKUR      = 7  // kur – Key Update Request
	BodyTagKUP      = 8  // kup – Key Update Response
	BodyTagRR       = 11 // rr  – Revocation Request
	BodyTagRP       = 12 // rp  – Revocation Response
	BodyTagCCR      = 13 // ccr – Cross Certification Request  (RFC 4210 §5.3.11)
	BodyTagCCP      = 14 // ccp – Cross Certification Response (RFC 4210 §5.3.12)
	BodyTagNested   = 20 // nested – wrapped/added-protection or batched PKIMessages (RFC 4210 §5.1.3 / RFC 9483 §5.2.2)
	BodyTagCertConf = 24 // certConf – Certificate Confirmation
	BodyTagPKIConf  = 19 // pkiConf  – PKI Confirmation
	BodyTagGenMsg   = 21 // genm     – General Message  (RFC 4210 §5.3.19 / RFC 9483 §4.3)
	BodyTagGenRep   = 22 // genp     – General Response (RFC 4210 §5.3.20 / RFC 9483 §4.3)
	BodyTagError    = 23 // error    – Error Message
	BodyTagPollReq  = 25 // pollReq  – Polling Request   (RFC 4210 §5.3.22)
	BodyTagPollRep  = 26 // pollRep  – Polling Response  (RFC 4210 §5.3.22)

	// pvnoCMP2000 is the protocol version for RFC 4210 / RFC 9810 (cmp2000 = 2).
	// Default for messages that do not need cmp2021 syntax (RFC 9810 §7 line 3748).
	PVNOCMP2000 = 2
	// pvnoCMP2021 is the protocol version for RFC 9810 (cmp2021 = 3). MUST be
	// used when EnvelopedData, hashAlg in CertStatus, POPOPrivKey with agreeMAC,
	// or ckuann with RootCaKeyUpdateContent are present (RFC 9810 §7 line 3750).
	PVNOCMP2021 = 3

	// pkiStatusAccepted is RFC 4210 §5.2.3 PKIStatus value 0.
	PKIStatusAccepted = 0
	// pkiStatusRejection is RFC 4210 §5.2.3 PKIStatus value 2.
	PKIStatusRejection = 2

	// PKIFailureInfo bit positions (RFC 9810 §5.1.3 / Appendix B PKIFailureInfo
	// BIT STRING enumeration). RFC 9483 §3.6.4 requires error responses to
	// include a failInfo; the table below enumerates every bit the server can
	// currently emit. Bit numbers are LITERAL RFC values — they are written on
	// the wire and consumed by every other CMP implementation, so even a single
	// off-by-one here means EEs see the wrong failure reason.
	PKIFailureInfoBadAlg              = 0  // unrecognized or unsupported algorithm identifier
	PKIFailureInfoBadMessageCheck     = 1  // integrity check (e.g. signature) failed
	PKIFailureInfoBadRequest          = 2  // request not permitted / malformed for the server
	PKIFailureInfoBadTime             = 3  // messageTime not sufficiently close to system time
	PKIFailureInfoBadCertID           = 4  // no certificate could be found matching the request
	PKIFailureInfoBadDataFormat       = 5  // the data submitted has the wrong format
	PKIFailureInfoWrongAuthority      = 6  // the authority named in the request differs from the one creating the response
	PKIFailureInfoIncorrectData       = 7  // requester's data is incorrect (notary services)
	PKIFailureInfoMissingTimeStamp    = 8  // a required timestamp was missing from the message
	PKIFailureInfoBadPOP              = 9  // proof-of-possession failed
	PKIFailureInfoCertRevoked         = 10 // referenced/protection certificate is revoked
	PKIFailureInfoCertConfirmed       = 11 // certificate was already confirmed (duplicate certConf, RFC 9483 §4.1.1)
	PKIFailureInfoWrongIntegrity      = 12 // wrong integrity type: MAC-based protection where a signature was required (RFC 9483 §3.5)
	PKIFailureInfoBadRecipientNonce   = 13 // recipNonce did not match the expected senderNonce
	PKIFailureInfoTimeNotAvailable    = 14 // the TSA's time source is not available
	PKIFailureInfoUnacceptedPolicy    = 15 // the requested policy is not supported by the CA
	PKIFailureInfoUnacceptedExtension = 16 // the requested extension is not supported by the CA
	PKIFailureInfoAddInfoNotAvailable = 17 // request needs information the server cannot supply (RFC 9810 §5.1.3)
	PKIFailureInfoBadSenderNonce      = 18 // sender nonce missing or too short (RFC 9483 §3.5)
	PKIFailureInfoBadCertTemplate     = 19 // submitted CertTemplate is incomplete or invalid
	PKIFailureInfoSignerNotTrusted    = 20 // protection signer cert not trusted / no trust anchor (RFC 9483 §3.5)
	PKIFailureInfoTransactionIDInUse  = 21 // transactionID collides with an in-flight one (RFC 9810 §3.1)
	PKIFailureInfoUnsupportedVersion  = 22 // pvno not understood (RFC 9810 §7 / RFC 9483 §3.5)
	PKIFailureInfoNotAuthorized       = 23 // sender not authorized for the request (RFC 9810 §3.1)
	PKIFailureInfoSystemUnavail       = 24 // the request cannot be handled due to system unavailability
	PKIFailureInfoSystemFailure       = 25
	PKIFailureInfoDuplicateCertReq    = 26 // the certificate request duplicates an already-issued certificate
	// pkiStatusWaiting is RFC 4210 §5.2.3 PKIStatus value 3, sent on the initial
	// ip/cp/kup response in async-issuance mode to tell the EE that the
	// certificate is not yet available and it should poll for it later.
	PKIStatusWaiting = 3
)

// oidImplicitConfirm is id-it-implicitConfirm (1.3.6.1.5.5.7.4.13).
// When present in the request PKIHeader generalInfo field, the EE signals that
// it supports implicit certificate confirmation per RFC 4210 §5.3.2.
var oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}

// oidOrigPKIMessage is id-it-origPKIMessage (1.3.6.1.5.5.7.4.15). When an RA
// forwards a request to the CA it MAY embed the EE's original PKIMessage(s) in
// the header generalInfo under this OID so the CA can verify what the EE
// actually signed (RFC 9483 §5.2.3 / RFC 9480 §5.2). The value is
// OrigPKIMessageValue ::= PKIMessages (a SEQUENCE OF PKIMessage).
var oidOrigPKIMessage = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 15}

// MAC-based protection algorithm OIDs that are explicitly rejected.
// Only signature-based protection (RSA, ECDSA, Ed25519) is accepted.
var (
	oidPasswordBasedMAC = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13} // id-PasswordBasedMac  RFC 4210
	oidDHBasedMAC       = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 30} // id-DHBasedMac        RFC 4210
)

// hashFromSignatureAlgOID maps a signature algorithm OID to the hash function
// used to digest the signed data. Ed25519 returns crypto.Hash(0) because it
// hashes internally. Returns an error for unknown OIDs.
//
// SHA-1 and SHA-224 are deliberately NOT accepted: RFC 9481 §3 (MSG_SIG_ALG)
// only lists SHA-256, SHA-384, SHA-512 (with RSA/ECDSA) and Ed25519. SHA-1 has
// been deprecated for digital signatures by NIST and is no longer compliant.
//
// Used for incoming request-protection verification and response algorithm
// selection.
func HashFromSignatureAlgOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch oid.String() {
	case "1.2.840.113549.1.1.11":
		return crypto.SHA256, nil
	case "1.2.840.113549.1.1.12":
		return crypto.SHA384, nil
	case "1.2.840.113549.1.1.13":
		return crypto.SHA512, nil
	case "1.2.840.113549.1.1.10":
		return 0, fmt.Errorf("RSASSA-PSS signature requires parameters to be parsed (use hashFromSignatureAlgID)")
	case "1.2.840.10045.4.3.2":
		return crypto.SHA256, nil
	case "1.2.840.10045.4.3.3":
		return crypto.SHA384, nil
	case "1.2.840.10045.4.3.4":
		return crypto.SHA512, nil
	case "1.3.101.112":
		return crypto.Hash(0), nil
	case "1.2.840.113549.1.1.5",
		"1.2.840.10045.4.1",
		"1.2.840.10045.4.3.1":
		return 0, fmt.Errorf("signature algorithm %s is deprecated and not permitted by RFC 9481 §3 (MSG_SIG_ALG)", oid)
	default:
		return 0, fmt.Errorf("unsupported signature algorithm OID %s", oid)
	}
}

// hashFromSignatureAlgID is the structural counterpart of
// hashFromSignatureAlgOID that consults the AlgorithmIdentifier.Parameters
// field for algorithms whose hash is encoded there (notably id-RSASSA-PSS,
// RFC 4055 §3.1). For algorithms whose hash is implied by the OID it behaves
// identically to hashFromSignatureAlgOID.
func HashFromSignatureAlgID(algID pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	if algID.Algorithm.String() == "1.2.840.113549.1.1.10" {
		// RSASSA-PSS-params ::= SEQUENCE {
		//   hashAlgorithm [0] AlgorithmIdentifier DEFAULT sha1Identifier,
		//   ... (MGF, saltLength, trailerField — not needed for hash selection)
		// }
		// Per RFC 4055, the DEFAULT for hashAlgorithm is SHA-1; we reject the
		// default because SHA-1 is not permitted (RFC 9481 §3).
		var pssParams struct {
			HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
		}
		if len(algID.Parameters.FullBytes) > 0 {
			if _, err := asn1.Unmarshal(algID.Parameters.FullBytes, &pssParams); err != nil {
				return 0, fmt.Errorf("RSASSA-PSS parameters: %w", err)
			}
		}
		if len(pssParams.HashAlgorithm.Algorithm) == 0 {
			return 0, fmt.Errorf("RSASSA-PSS without explicit hashAlgorithm defaults to SHA-1, which is not permitted (RFC 9481 §3)")
		}
		return HashFromHashAlgOID(pssParams.HashAlgorithm.Algorithm)
	}
	return HashFromSignatureAlgOID(algID.Algorithm)
}

// hashFromHashAlgOID maps a hash algorithm OID (e.g. id-sha256) to crypto.Hash.
// Distinct from hashFromSignatureAlgOID, which expects composite signature
// algorithm OIDs (e.g. ecdsa-with-SHA256).
func HashFromHashAlgOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch oid.String() {
	case "2.16.840.1.101.3.4.2.1":
		return crypto.SHA256, nil
	case "2.16.840.1.101.3.4.2.2":
		return crypto.SHA384, nil
	case "2.16.840.1.101.3.4.2.3":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm OID %s", oid)
	}
}

// rawPKIMessage captures the Header and Body of an incoming PKIMessage for
// body-tag dispatch. Protection and ExtraCerts are omitted here; use
// rawPKIMessageFull when those fields are needed.
type RawPKIMessage struct {
	Header asn1.RawValue
	Body   asn1.RawValue
}

// rawPKIMessageFull captures all four top-level fields of a PKIMessage so that
// the controller can verify incoming signature-based protection.
//
// CMP uses tagged protection [0] and extraCerts [1] fields.
// We decode both as explicit wrappers so Go preserves the inner ASN.1 objects:
// protection contains a BIT STRING, and extraCerts contains a SEQUENCE OF
// certificates that Go can expose as []asn1.RawValue.
type RawPKIMessageFull = RawMessage

type RequestPKIHeader struct {
	PVNO          int
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	MessageTime   time.Time                // optional [0] GeneralizedTime; zero when absent (RFC 9483 §3.1)
	ProtectionAlg pkix.AlgorithmIdentifier // full algorithm identifier including parameters (RFC 4055 PSS)
	SenderKID     []byte                   // optional [2] OCTET STRING — SubjectKeyIdentifier (RFC 9483 §3.1)
	TransactionID []byte                   `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5,omitempty"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6,omitempty"`
	GeneralInfo   []asn1.RawValue          // decoded from [8] EXPLICIT SEQUENCE; empty when absent

	// ResponseSenderNonce, if non-nil, is used as the SenderNonce on the
	// outbound response instead of generating a fresh random nonce.  This
	// lets the enrollment handler pre-generate the nonce, persist it in the
	// transaction store, and guarantee the certConf handler can later verify
	// that the EE's recipNonce matches what we sent (RFC 4210 §5.1.1).
	ResponseSenderNonce []byte

	// ResponseImplicitConfirm, when true, causes buildResponseHeader to add the
	// id-it-implicitConfirm OID to the response generalInfo. Set by enrollment
	// handlers when the EE requested implicit confirmation AND the DMS is
	// configured for IMPLICIT confirmation mode, signalling to the EE that the
	// server agrees to skip the certConf step (RFC 9483 §4.1.1 / RFC 4210 §5.3.2).
	ResponseImplicitConfirm bool
}

// certStatusASN1 is the server-side parse target for one CertStatus entry
// inside a certConf message body (RFC 9480 §2.10):
//
//	CertStatus ::= SEQUENCE {
//	    certHash   OCTET STRING,
//	    certReqId  INTEGER,
//	    statusInfo PKIStatusInfo               OPTIONAL,
//	    hashAlg    [0] AlgorithmIdentifier     OPTIONAL  -- RFC 9480
//	}
//
// When hashAlg is absent, SHA-256 is assumed (RFC 9481 §3.3).
// When present, it indicates the hash used by the EE to compute certHash.
type CertStatus struct {
	CertHash   []byte
	CertReqID  int
	StatusInfo PKIStatusInfo `asn1:"optional"`
	// HashAlgOID is the algorithm OID from the optional hashAlg [0] field.
	// Empty (nil) means SHA-256 per default.
	HashAlgOID asn1.ObjectIdentifier
}

// serverCertResponse is one entry in a CP (tag 3) or KUP (tag 8) body:
//
//	CertResponse ::= SEQUENCE {
//	    certReqId           INTEGER,
//	    status              PKIStatusInfo,
//	    certifiedKeyPair    CertifiedKeyPair OPTIONAL,
//	    rspInfo             OCTET STRING     OPTIONAL
//	}
type ServerCertResponse struct {
	CertReqID        int
	Status           PKIStatusInfo
	CertifiedKeyPair asn1.RawValue `asn1:"optional"`
}

// serverCertRepMessage is the content of a CP (tag 3) or KUP (tag 8) body:
//
//	CertRepMessage ::= SEQUENCE {
//	    caPubs    [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
//	    response  SEQUENCE OF CertResponse
//	}
//
// caPubs is omitted in this implementation.
type ServerCertRepMessage struct {
	Responses []ServerCertResponse
}

// PKIStatus represents the PKIStatus INTEGER from RFC 4210 §5.2.3.
//
//	PKIStatus ::= INTEGER {
//	    accepted                (0),
//	    grantedWithMods         (1),
//	    rejection               (2),
//	    waiting                 (3),
//	    revocationWarning       (4),
//	    revocationNotification  (5),
//	    keyUpdateWarning        (6)
//	}
type PKIStatus int

// PKIFreeText is a SEQUENCE of UTF8Strings (RFC 4210 §5.1.1).
//
//	PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
type PKIFreeText []asn1.RawValue

// PKIStatusInfo carries status information in CMP responses (RFC 4210 §5.2.3).
//
//	PKIStatusInfo ::= SEQUENCE {
//	    status        PKIStatus,
//	    statusString  PKIFreeText    OPTIONAL,
//	    failInfo      PKIFailureInfo OPTIONAL
//	}
type PKIStatusInfo struct {
	Raw          asn1.RawContent
	Status       PKIStatus
	StatusString PKIFreeText    `asn1:"optional,omitempty"`
	FailInfo     asn1.BitString `asn1:"optional,omitempty"`
}

// ErrorMsgContent is the body of an error PKIMessage (RFC 4210 §5.2.21).
//
//	ErrorMsgContent ::= SEQUENCE {
//	    pKIStatusInfo  PKIStatusInfo,
//	    errorCode      INTEGER           OPTIONAL,
//	    errorDetails   PKIFreeText       OPTIONAL
//	}
type ErrorMsgContent struct {
	PKIStatusInfo PKIStatusInfo
	ErrorCode     int         `asn1:"optional"`
	ErrorDetail   PKIFreeText `asn1:"optional"`
}

// nullDNGeneralName builds a GeneralName directoryName carrying an empty
// RDNSequence (NULL-DN).
//
//	GeneralName ::= CHOICE { directoryName [4] Name }
//	Name        ::= RDNSequence
//
// RFC 9483 §3.1 line 713 mandates NULL-DN as the response PKIHeader Sender
// when no protection certificate or shared secret is available to identify
// the responder, and line 803 mandates it as the Recipient when the intended
// recipient name is unknown.
func NullDNGeneralName() asn1.RawValue {
	name := struct {
		RDNSequence pkix.RDNSequence
	}{RDNSequence: pkix.RDNSequence{}}
	der, _ := asn1.MarshalWithParams(name, "tag:4,optional")
	return asn1.RawValue{FullBytes: der}
}

// defaultSenderGeneralName returns the NULL-DN GeneralName used as the
// response PKIHeader Sender when the DMS has no protection certificate
// configured (RFC 9483 §3.1 line 713).
func DefaultSenderGeneralName() asn1.RawValue {
	return NullDNGeneralName()
}

// defaultRecipientGeneralName returns the NULL-DN GeneralName used as the
// response PKIHeader Recipient when the intended recipient cannot be derived
// from the incoming request (RFC 9483 §3.1 line 803).
func DefaultRecipientGeneralName() asn1.RawValue {
	return NullDNGeneralName()
}
