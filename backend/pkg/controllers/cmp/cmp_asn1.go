package cmp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// CMP PKIBody CHOICE tag numbers (RFC 4210 §5.1.2 / RFC 9480).
const (
	cmpBodyTagIR       = 0  // ir  – Initialization Request
	cmpBodyTagIP       = 1  // ip  – Initialization Response
	cmpBodyTagCR       = 2  // cr  – Certificate Request
	cmpBodyTagCP       = 3  // cp  – Certificate Response
	cmpBodyTagP10CR    = 4  // p10cr – PKCS#10 Certification Request (RFC 9483 §4.1.4)
	cmpBodyTagPopDecc  = 5  // popdecc – POPO Challenge (RFC 4210bis §5.2.8.3)
	cmpBodyTagPopDecr  = 6  // popdecr – POPO Decryption Response (RFC 4210bis §5.2.8.3)
	cmpBodyTagKUR      = 7  // kur – Key Update Request
	cmpBodyTagKUP      = 8  // kup – Key Update Response
	cmpBodyTagRR       = 11 // rr  – Revocation Request
	cmpBodyTagRP       = 12 // rp  – Revocation Response
	cmpBodyTagCCR      = 13 // ccr – Cross Certification Request  (RFC 4210 §5.3.11)
	cmpBodyTagCCP      = 14 // ccp – Cross Certification Response (RFC 4210 §5.3.12)
	cmpBodyTagNested   = 20 // nested – wrapped/added-protection or batched PKIMessages (RFC 4210 §5.1.3 / RFC 9483 §5.2.2)
	cmpBodyTagCertConf = 24 // certConf – Certificate Confirmation
	cmpBodyTagPKIConf  = 19 // pkiConf  – PKI Confirmation
	cmpBodyTagGenMsg   = 21 // genm     – General Message  (RFC 4210 §5.3.19 / RFC 9483 §4.3)
	cmpBodyTagGenRep   = 22 // genp     – General Response (RFC 4210 §5.3.20 / RFC 9483 §4.3)
	cmpBodyTagError    = 23 // error    – Error Message
	cmpBodyTagPollReq  = 25 // pollReq  – Polling Request   (RFC 4210 §5.3.22)
	cmpBodyTagPollRep  = 26 // pollRep  – Polling Response  (RFC 4210 §5.3.22)

	// pvnoCMP2000 is the protocol version for RFC 4210 / RFC 9810 (cmp2000 = 2).
	// Default for messages that do not need cmp2021 syntax (RFC 9810 §7 line 3748).
	pvnoCMP2000 = 2
	// pvnoCMP2021 is the protocol version for RFC 9810 (cmp2021 = 3). MUST be
	// used when EnvelopedData, hashAlg in CertStatus, POPOPrivKey with agreeMAC,
	// or ckuann with RootCaKeyUpdateContent are present (RFC 9810 §7 line 3750).
	pvnoCMP2021 = 3

	// pkiStatusAccepted is RFC 4210 §5.2.3 PKIStatus value 0.
	pkiStatusAccepted = 0
	// pkiStatusRejection is RFC 4210 §5.2.3 PKIStatus value 2.
	pkiStatusRejection = 2

	// PKIFailureInfo bit positions (RFC 9810 §5.1.3 / Appendix B PKIFailureInfo
	// BIT STRING enumeration). RFC 9483 §3.6.4 requires error responses to
	// include a failInfo; the table below enumerates every bit the server can
	// currently emit. Bit numbers are LITERAL RFC values — they are written on
	// the wire and consumed by every other CMP implementation, so even a single
	// off-by-one here means EEs see the wrong failure reason.
	pkiFailureInfoBadAlg              = 0  // unrecognized or unsupported algorithm identifier
	pkiFailureInfoBadMessageCheck     = 1  // integrity check (e.g. signature) failed
	pkiFailureInfoBadRequest          = 2  // request not permitted / malformed for the server
	pkiFailureInfoBadTime             = 3  // messageTime not sufficiently close to system time
	pkiFailureInfoBadCertId           = 4  // no certificate could be found matching the request
	pkiFailureInfoBadDataFormat       = 5  // the data submitted has the wrong format
	pkiFailureInfoIncorrectData       = 7  // requester's data is incorrect (notary services)
	pkiFailureInfoBadPOP              = 9  // proof-of-possession failed
	pkiFailureInfoCertRevoked         = 10 // referenced/protection certificate is revoked
	pkiFailureInfoCertConfirmed       = 11 // certificate was already confirmed (duplicate certConf, RFC 9483 §4.1.1)
	pkiFailureInfoWrongIntegrity      = 12 // wrong integrity type: MAC-based protection where a signature was required (RFC 9483 §3.5)
	pkiFailureInfoBadRecipientNonce   = 13 // recipNonce did not match the expected senderNonce
	pkiFailureInfoAddInfoNotAvailable = 17 // request needs information the server cannot supply (RFC 9810 §5.1.3)
	pkiFailureInfoBadSenderNonce      = 18 // sender nonce missing or too short (RFC 9483 §3.5)
	pkiFailureInfoBadCertTemplate     = 19 // submitted CertTemplate is incomplete or invalid
	pkiFailureInfoSignerNotTrusted    = 20 // protection signer cert not trusted / no trust anchor (RFC 9483 §3.5)
	pkiFailureInfoTransactionIDInUse  = 21 // transactionID collides with an in-flight one (RFC 9810 §3.1)
	pkiFailureInfoUnsupportedVersion  = 22 // pvno not understood (RFC 9810 §7 / RFC 9483 §3.5)
	pkiFailureInfoNotAuthorized       = 23 // sender not authorized for the request (RFC 9810 §3.1)
	pkiFailureInfoSystemFailure       = 25
	// pkiStatusWaiting is RFC 4210 §5.2.3 PKIStatus value 3, sent on the initial
	// ip/cp/kup response in async-issuance mode to tell the EE that the
	// certificate is not yet available and it should poll for it later.
	pkiStatusWaiting = 3
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
	oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13} // id-PasswordBasedMac  RFC 4210
	oidDHBasedMac       = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 30} // id-DHBasedMac        RFC 4210
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
func hashFromSignatureAlgOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch oid.String() {
	case "1.2.840.113549.1.1.11": // sha256WithRSAEncryption
		return crypto.SHA256, nil
	case "1.2.840.113549.1.1.12": // sha384WithRSAEncryption
		return crypto.SHA384, nil
	case "1.2.840.113549.1.1.13": // sha512WithRSAEncryption
		return crypto.SHA512, nil
	case "1.2.840.113549.1.1.10": // id-RSASSA-PSS — params carry hash/MGF (RFC 4055)
		return 0, fmt.Errorf("RSASSA-PSS signature requires parameters to be parsed (use hashFromSignatureAlgID)")
	case "1.2.840.10045.4.3.2": // ecdsaWithSHA256
		return crypto.SHA256, nil
	case "1.2.840.10045.4.3.3": // ecdsaWithSHA384
		return crypto.SHA384, nil
	case "1.2.840.10045.4.3.4": // ecdsaWithSHA512
		return crypto.SHA512, nil
	case "1.3.101.112": // id-Ed25519
		return crypto.Hash(0), nil
	case "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
		"1.2.840.10045.4.1",   // ecdsa-with-SHA1
		"1.2.840.10045.4.3.1": // ecdsa-with-SHA224
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
func hashFromSignatureAlgID(algID pkix.AlgorithmIdentifier) (crypto.Hash, error) {
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
		return hashFromHashAlgOID(pssParams.HashAlgorithm.Algorithm)
	}
	return hashFromSignatureAlgOID(algID.Algorithm)
}

// hashFromHashAlgOID maps a hash algorithm OID (e.g. id-sha256) to crypto.Hash.
// Distinct from hashFromSignatureAlgOID, which expects composite signature
// algorithm OIDs (e.g. ecdsa-with-SHA256).
func hashFromHashAlgOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
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
type rawPKIMessage struct {
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
type rawPKIMessageFull struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

type requestPKIHeader struct {
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
type certStatusASN1 struct {
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
type serverCertResponse struct {
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
type serverCertRepMessage struct {
	Responses []serverCertResponse
}

// marshalEncryptedKeyChoice wraps the content of a CMS EnvelopedData as the
// IMPLICIT [0] envelopedData alternative of the EncryptedKey CHOICE:
//
//	EncryptedKey ::= CHOICE { encryptedValue EncryptedValue,  -- deprecated
//	                          envelopedData [0] EnvelopedData }
//
// Used wherever RFC 9480/9810 places an EncryptedKey — CertifiedKeyPair's
// privateKey (wrapped EXPLICIT [0] by marshalKGACertifiedKeyPair) and
// CertOrEncCert's encryptedCert (wrapped IMPLICIT [1] by
// marshalCertOrEncCertEncrypted) both choose this same alternative.
func marshalEncryptedKeyChoice(envelopedDataDER []byte) ([]byte, error) {
	var env asn1.RawValue
	if _, err := asn1.Unmarshal(envelopedDataDER, &env); err != nil {
		return nil, fmt.Errorf("decode EnvelopedData: %w", err)
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: env.Bytes,
	})
}

// marshalCertOrEncCert encodes a certificate DER as the `certificate`
// alternative of the CertOrEncCert CHOICE.
//
//	CertOrEncCert ::= CHOICE {
//	    certificate   [0] CMPCertificate,
//	    encryptedCert [1] EncryptedKey }
//
// OpenSSL accepts this in the same shape used by caf-pki-local-agent:
// a context-specific [0] wrapper whose payload is the full certificate DER.
func marshalCertOrEncCert(certDER []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certDER,
	})
}

// marshalCertOrEncCertEncrypted encodes envelopedDataDER (a CMS EnvelopedData
// whose decrypted content is the raw CMPCertificate DER) as the
// `encryptedCert` alternative of the CertOrEncCert CHOICE, IMPLICIT [1]
// wrapping the EncryptedKey CHOICE's envelopedData [0] alternative — i.e.
// [1]{ [0]{ envDataBody } } on the wire. Used for the encrCert
// proof-of-possession method (RFC 9483 §4.1.4 / RFC 4210bis §5.2.8.4): the
// issued certificate is delivered confidentiality-protected to the
// requester's own (not-yet-certified) public key, so only the actual key
// holder can recover and use it.
func marshalCertOrEncCertEncrypted(envelopedDataDER []byte) ([]byte, error) {
	encKeyChoice, err := marshalEncryptedKeyChoice(envelopedDataDER)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: encKeyChoice,
	})
}

// marshalCertifiedKeyPair wraps the certOrEncCert DER inside a
// CertifiedKeyPair SEQUENCE:
//
//	CertifiedKeyPair ::= SEQUENCE {
//	    certOrEncCert  CertOrEncCert,
//	    privateKey [0] EncryptedValue OPTIONAL, ... }
func marshalCertifiedKeyPair(certOrEncCertDER []byte) ([]byte, error) {
	return asn1.Marshal(struct {
		CertOrEncCert asn1.RawValue
	}{
		CertOrEncCert: asn1.RawValue{FullBytes: certOrEncCertDER},
	})
}

// certRequestRejection is returned by decodeFirstCertReq (and POPO checks) when
// the failure is a cert-request-level protocol violation rather than a
// wire-format decode error. The handler routes these to an ip/cp CertRepMessage
// with PKIStatus rejection (RFC 9483 §4.1 / RFC 9810 §5.2.3) rather than
// using the error body type.
type certRequestRejection struct {
	CertReqID   int
	Reason      string
	FailInfoBit int
}

func (e *certRequestRejection) Error() string { return e.Reason }

// marshalCertRepRejectionBody assembles a CertRepMessage with a single
// CertResponse whose status is rejection. Used for cert-request-level failures
// (bad certReqId, missing subject, bad POP, etc.) where RFC 9483 §4.1 requires
// an ip/cp response body rather than an error body.
func marshalCertRepRejectionBody(certReqID int, reason string, failInfoBit int) ([]byte, error) {
	certResp := serverCertResponse{
		CertReqID: certReqID,
		Status: PKIStatusInfo{
			Status: PKIStatus(pkiStatusRejection),
			StatusString: PKIFreeText{
				asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(reason)},
			},
			FailInfo: encodePKIFailureInfo([]int{failInfoBit}),
		},
	}
	msg := serverCertRepMessage{Responses: []serverCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalCertRepBody assembles the raw CertRepMessage DER. The PKIBody
// context-specific wrapper is added by sendRawBody.
// certReqID is the certReqId from the corresponding CertRequest.
// certDER is the DER of the issued certificate.
func marshalCertRepBody(bodyTag, certReqID int, certDER []byte) ([]byte, error) {
	return marshalCertRepBodyWithStatus(bodyTag, certReqID, int(PKIStatus(0)), certDER)
}

// marshalCertRepBodyWithStatus is marshalCertRepBody with an explicit
// PKIStatus. RFC 4210 §5.2.3 allows a successful CertResponse to carry either
// accepted (0) or grantedWithMods (1); the latter signals the issued
// certificate differs from what the request asked for (e.g. the CA dropped an
// unrecognized/invalid requested extension per RFC 9483 §5).
func marshalCertRepBodyWithStatus(bodyTag, certReqID, statusCode int, certDER []byte) ([]byte, error) {
	_ = bodyTag
	certOrEncCert, err := marshalCertOrEncCert(certDER)
	if err != nil {
		return nil, err
	}
	ckpDER, err := marshalCertifiedKeyPair(certOrEncCert)
	if err != nil {
		return nil, err
	}
	certResp := serverCertResponse{
		CertReqID:        certReqID,
		Status:           PKIStatusInfo{Status: PKIStatus(statusCode)},
		CertifiedKeyPair: asn1.RawValue{FullBytes: ckpDER},
	}
	msg := serverCertRepMessage{Responses: []serverCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalCertRepBodyEncrypted is marshalCertRepBodyWithStatus for the encrCert
// proof-of-possession method: the CertifiedKeyPair's certOrEncCert carries the
// encryptedCert alternative (envelopedDataDER, a CMS EnvelopedData whose
// content is the raw issued-certificate DER) instead of a plain certificate.
func marshalCertRepBodyEncrypted(certReqID, statusCode int, envelopedDataDER []byte) ([]byte, error) {
	certOrEncCert, err := marshalCertOrEncCertEncrypted(envelopedDataDER)
	if err != nil {
		return nil, err
	}
	ckpDER, err := marshalCertifiedKeyPair(certOrEncCert)
	if err != nil {
		return nil, err
	}
	certResp := serverCertResponse{
		CertReqID:        certReqID,
		Status:           PKIStatusInfo{Status: PKIStatus(statusCode)},
		CertifiedKeyPair: asn1.RawValue{FullBytes: ckpDER},
	}
	msg := serverCertRepMessage{Responses: []serverCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalKGACertifiedKeyPair builds a CertifiedKeyPair carrying both the issued
// certificate and the centrally generated private key, per RFC 9483 §4.1.6:
//
//	CertifiedKeyPair ::= SEQUENCE {
//	    certOrEncCert       CertOrEncCert,
//	    privateKey      [0] EncryptedKey OPTIONAL, ... }
//	EncryptedKey ::= CHOICE { encryptedValue EncryptedValue,
//	                          envelopedData [0] EnvelopedData }
//
// The tagging (verified against the compliance validator's pyasn1 schema) is:
// privateKey is EXPLICIT [0] wrapping the EncryptedKey CHOICE, and the chosen
// envelopedData alternative is IMPLICIT [0] EnvelopedData. On the wire this is a
// context-[0]-constructed value containing a context-[0]-constructed value
// containing the EnvelopedData SEQUENCE body — i.e. [0]{ [0]{ envDataBody } }.
func marshalKGACertifiedKeyPair(certOrEncCertDER, envelopedDataDER []byte) ([]byte, error) {
	encKeyChoice, err := marshalEncryptedKeyChoice(envelopedDataDER)
	if err != nil {
		return nil, err
	}
	// Wrap the CHOICE in the EXPLICIT [0] privateKey tag.
	privateKey, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: encKeyChoice,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		CertOrEncCert asn1.RawValue
		PrivateKey    asn1.RawValue
	}{
		CertOrEncCert: asn1.RawValue{FullBytes: certOrEncCertDER},
		PrivateKey:    asn1.RawValue{FullBytes: privateKey},
	})
}

// marshalKGACertRepBody assembles a CertRepMessage (ip/cp/kup) whose single
// CertResponse delivers both the issued certificate and the centrally generated
// private key (RFC 9483 §4.1.6). envelopedDataDER is the DER of the CMS
// EnvelopedData produced by core/pkg/kga.
func marshalKGACertRepBody(certReqID, statusCode int, certDER, envelopedDataDER []byte) ([]byte, error) {
	certOrEncCert, err := marshalCertOrEncCert(certDER)
	if err != nil {
		return nil, err
	}
	ckpDER, err := marshalKGACertifiedKeyPair(certOrEncCert, envelopedDataDER)
	if err != nil {
		return nil, err
	}
	certResp := serverCertResponse{
		CertReqID:        certReqID,
		Status:           PKIStatusInfo{Status: PKIStatus(statusCode)},
		CertifiedKeyPair: asn1.RawValue{FullBytes: ckpDER},
	}
	msg := serverCertRepMessage{Responses: []serverCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalPKIConfBody produces the raw body payload for pkiConf.
func marshalPKIConfBody() ([]byte, error) {
	return asn1.Marshal(asn1.NullRawValue)
}

// marshalCertRepWaitingBody produces a CertRepMessage where the single
// CertResponse has PKIStatus = waiting (3) and no CertifiedKeyPair, used for
// the initial ip/cp/kup response in async-issuance mode (RFC 9483 §4.4).
//
// The EE recognises this as "issuance deferred" and is expected to switch to
// the pollReq flow: it sends pollReq carrying the same certReqId, the server
// replies with pollRep(checkAfter) while still PENDING, and finally returns a
// fresh ip body with the cert once the worker has populated it.
func marshalCertRepWaitingBody(certReqID int) ([]byte, error) {
	certResp := serverCertResponse{
		CertReqID: certReqID,
		Status:    PKIStatusInfo{Status: PKIStatus(pkiStatusWaiting)},
		// CertifiedKeyPair intentionally omitted (zero value of RawValue) — the
		// asn1:"optional" tag means it disappears from the wire encoding.
	}
	msg := serverCertRepMessage{Responses: []serverCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// pollRepEntry is one entry of PollRepContent per RFC 4210 §5.3.22:
//
//	PollRepContent ::= SEQUENCE OF SEQUENCE {
//	    certReqId    INTEGER,
//	    checkAfter   INTEGER,             -- time in seconds
//	    reason       PKIFreeText OPTIONAL
//	}
//
// The optional `reason` PKIFreeText is intentionally omitted; OpenSSL clients
// don't display it usefully and the absence is well-formed.
type pollRepEntry struct {
	CertReqID  int
	CheckAfter int
}

// marshalPollRepBody produces the raw PollRepContent DER for a pollRep response
// where the EE should retry after `checkAfterSeconds`. Always carries exactly
// one entry — Lamassu issues one cert per CMP transaction, so there is at most
// one outstanding certReqId.
//
// PollRepContent is "SEQUENCE OF SEQUENCE { certReqId, checkAfter, … }". Go's
// encoding/asn1 produces SEQUENCE OF directly from a slice — wrapping the slice
// in a struct adds an extra surrounding SEQUENCE that breaks RFC 4210 §5.3.22.
func marshalPollRepBody(certReqID, checkAfterSeconds int) ([]byte, error) {
	return asn1.Marshal([]pollRepEntry{
		{CertReqID: certReqID, CheckAfter: checkAfterSeconds},
	})
}

// decodePollReqContent parses a pollReq body and returns the first certReqId
// it carries. Per RFC 4210 §5.3.22 the body is:
//
//	PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER }
//
// We only support a single entry per transaction (one cert per CMP exchange),
// matching what every standard CMP client emits.
func decodePollReqContent(bodyBytes []byte) (int, error) {
	// The [25] EXPLICIT wrapping is stripped by the Gin dispatch layer; what
	// arrives here is the SEQUENCE OF DER itself.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &outer); err != nil {
		return 0, fmt.Errorf("PollReqContent: %w", err)
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return 0, fmt.Errorf("PollReqContent must be a SEQUENCE, got class=%d tag=%d", outer.Class, outer.Tag)
	}

	var entry asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &entry); err != nil {
		return 0, fmt.Errorf("PollReqContent entry: %w", err)
	}
	if entry.Class != asn1.ClassUniversal || entry.Tag != asn1.TagSequence {
		return 0, fmt.Errorf("PollReqContent entry must be a SEQUENCE, got class=%d tag=%d", entry.Class, entry.Tag)
	}

	var certReqID int
	if _, err := asn1.Unmarshal(entry.Bytes, &certReqID); err != nil {
		return 0, fmt.Errorf("certReqId: %w", err)
	}
	return certReqID, nil
}

// marshalErrorBody produces the raw ErrorMsgContent DER. The PKIBody wrapper is
// added by sendRawBody. When failInfoBits is non-empty, the corresponding bits
// of the PKIFailureInfo BIT STRING are set (RFC 4210 §5.1.3 / RFC 9483 §3.6.4
// — error responses SHOULD carry a failInfo).
func marshalErrorBody(status PKIStatus, reason string, failInfoBits ...int) ([]byte, error) {
	errMsg := ErrorMsgContent{
		PKIStatusInfo: PKIStatusInfo{
			Status: status,
			StatusString: PKIFreeText{
				asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(reason)},
			},
			FailInfo: encodePKIFailureInfo(failInfoBits),
		},
	}
	return asn1.Marshal(errMsg)
}

// encodePKIFailureInfo packs the given bit positions (RFC 4210 §5.1.3) into a
// DER-encodable BIT STRING. An empty input returns the zero value, which
// asn1:"optional,omitempty" elides from the wire.
func encodePKIFailureInfo(bits []int) asn1.BitString {
	if len(bits) == 0 {
		return asn1.BitString{}
	}
	highest := 0
	for _, b := range bits {
		if b > highest {
			highest = b
		}
	}
	nbytes := highest/8 + 1
	buf := make([]byte, nbytes)
	for _, b := range bits {
		// BIT STRING numbering: bit 0 is the MSB of the first byte.
		buf[b/8] |= 0x80 >> (uint(b) % 8)
	}
	return asn1.BitString{Bytes: buf, BitLength: highest + 1}
}

// marshalRevRepBody produces the raw RevRepContent DER for an rp (tag 12) body.
// RevRepContent ::= SEQUENCE { status SEQUENCE OF PKIStatusInfo, ... }
//
// The optional statusString is populated so RFC 9483 §4.2 clients (and the
// CMP test-suite's "Verify statusString" check) can read a human-readable
// reason. An empty statusText omits the field. failInfoBits, when non-empty,
// sets the PKIFailureInfo so rejection responses carry a populated BIT STRING
// (required by the suite's "Is Bit Set" check).
func marshalRevRepBody(status PKIStatus, statusText string, failInfoBits ...int) ([]byte, error) {
	type revRepContent struct {
		Status []PKIStatusInfo
	}
	info := PKIStatusInfo{Status: status}
	if statusText != "" {
		info.StatusString = PKIFreeText{
			asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(statusText)},
		}
	}
	if len(failInfoBits) > 0 {
		info.FailInfo = encodePKIFailureInfo(failInfoBits)
	}
	return asn1.Marshal(revRepContent{
		Status: []PKIStatusInfo{info},
	})
}

// crlReasonRemoveFromCRL is the RFC 5280 §5.3.1 CRLReason value (8) that the
// CMP revive operation (RFC 9483 §4.2) reuses to request un-revocation.
const crlReasonRemoveFromCRL = 8

// isKnownCRLReason reports whether code is a value defined by RFC 5280 §5.3.1.
// Value 7 is unused and any value ≥ 11 is out of range. removeFromCRL (8) is
// considered known because CMP uses it for revive requests.
func isKnownCRLReason(code int) bool {
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return true
	default:
		return false
	}
}

// revDetails holds the parsed fields of a single RevDetails entry (the
// CertTemplate plus its optional crlEntryDetails). The *DER fields are encoded
// so they can be DER-compared directly against the corresponding
// x509.Certificate.Raw* fields of the protection certificate.
type revDetails struct {
	SerialNumber    []byte // big-endian, leading 0x00 sign byte stripped
	HasSerial       bool
	IssuerDER       []byte // Name TLV, comparable to x509.Certificate.RawIssuer
	HasIssuer       bool
	SubjectDER      []byte // Name TLV, comparable to x509.Certificate.RawSubject
	HasSubject      bool
	PublicKeyDER    []byte // SubjectPublicKeyInfo SEQUENCE TLV, comparable to RawSubjectPublicKeyInfo
	HasPublicKey    bool
	Reasons         []int // decoded CRLReason ENUMERATED values, in encounter order
	ReasonExtCount  int   // number of CRLReason extensions present
	ReasonDecodeErr bool  // at least one CRLReason extension value failed to decode
	Version         int   // X.509 Version enum: v1(0), v2(1), v3(2)
	HasVersion      bool
	Extensions      []pkix.Extension // CertTemplate extensions [9], when present
	HasExtensions   bool
}

// decodeRevDetails parses the first RevDetails entry of an rr body.
// RevReqContent ::= SEQUENCE OF RevDetails
//
//	RevDetails    ::= SEQUENCE {
//	    certDetails     CertTemplate,
//	    crlEntryDetails Extensions OPTIONAL }
//
//	CertTemplate ::= SEQUENCE {
//		    version      [0], serialNumber [1] INTEGER, signingAlg [2],
//		    issuer       [3] Name, validity [4], subject [5] Name,
//		    publicKey    [6] SubjectPublicKeyInfo, ..., extensions [9] }
//
// Per RFC 4211, Name (a CHOICE) is EXPLICITLY tagged so issuer [3] / subject [5]
// wrap a full Name TLV; SubjectPublicKeyInfo [6] is IMPLICITLY tagged so its
// SEQUENCE tag is replaced and must be re-wrapped before comparison.
func decodeRevDetails(bodyBytes []byte) (*revDetails, error) {
	rd := &revDetails{}

	// bodyBytes is the content of [11] IMPLICIT — a SEQUENCE OF RevDetails TLV.
	var revDetailsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &revDetailsSeq); err != nil {
		return nil, fmt.Errorf("RevReqContent: %w", err)
	}

	// First element is a RevDetails SEQUENCE.
	var revDet asn1.RawValue
	if _, err := asn1.Unmarshal(revDetailsSeq.Bytes, &revDet); err != nil {
		return nil, fmt.Errorf("RevDetails: %w", err)
	}

	// RevDetails.certDetails is a CertTemplate SEQUENCE; what follows is the
	// optional crlEntryDetails Extensions.
	var certTemplate asn1.RawValue
	crlExtRest, err := asn1.Unmarshal(revDet.Bytes, &certTemplate)
	if err != nil {
		return nil, fmt.Errorf("CertTemplate: %w", err)
	}

	// Walk CertTemplate fields by context tag.
	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, fmt.Errorf("CertTemplate field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}
		switch field.Tag {
		case 0: // version [0] INTEGER (IMPLICIT) — Version ::= INTEGER { v1(0), v2(1), v3(2) }
			verDER, e := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: field.Bytes})
			var version int
			if e == nil {
				if _, e = asn1.Unmarshal(verDER, &version); e == nil {
					rd.Version = version
					rd.HasVersion = true
				}
			}
		case 1: // serialNumber [1] INTEGER
			sn := field.Bytes
			var inner asn1.RawValue
			if _, e := asn1.Unmarshal(field.Bytes, &inner); e == nil && inner.Tag == asn1.TagInteger {
				sn = inner.Bytes
			}
			// Strip the ASN.1 INTEGER sign-padding byte so the value matches
			// Lamassu's big.Int-normalized hex serial keys.
			if len(sn) > 1 && sn[0] == 0x00 {
				sn = sn[1:]
			}
			rd.SerialNumber = sn
			rd.HasSerial = len(sn) > 0
		case 3: // issuer [3] Name (EXPLICIT) → field.Bytes is the Name TLV
			rd.IssuerDER = field.Bytes
			rd.HasIssuer = true
		case 5: // subject [5] Name (EXPLICIT) → field.Bytes is the Name TLV
			rd.SubjectDER = field.Bytes
			rd.HasSubject = true
		case 6: // publicKey [6] SubjectPublicKeyInfo (IMPLICIT) → re-wrap as SEQUENCE
			spki, e := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSequence,
				IsCompound: true,
				Bytes:      field.Bytes,
			})
			if e == nil {
				rd.PublicKeyDER = spki
				rd.HasPublicKey = true
			}
		case 9: // extensions [9] Extensions (IMPLICIT SEQUENCE OF Extension) — same shape decodeFirstCertReq parses for ir/cr CertTemplates.
			rd.Extensions = parseCertTemplateExtensions(field.Bytes)
			rd.HasExtensions = true
		}
	}

	// crlEntryDetails (Extensions, OPTIONAL): collect every CRLReason value.
	if len(crlExtRest) > 0 {
		rd.Reasons, rd.ReasonExtCount, rd.ReasonDecodeErr = collectCRLReasons(crlExtRest)
	}
	return rd, nil
}

// collectCRLReasons scans an Extensions SEQUENCE and returns every CRLReason
// (2.5.29.21) ENUMERATED value found, the count of CRLReason extensions, and a
// flag indicating that at least one extension's value could not be decoded.
func collectCRLReasons(der []byte) (reasons []int, count int, decodeErr bool) {
	var extsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &extsSeq); err != nil {
		return nil, 0, false
	}
	remaining := extsSeq.Bytes
	oidCRLReason := asn1.ObjectIdentifier{2, 5, 29, 21}
	for len(remaining) > 0 {
		var ext asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &ext)
		if err != nil {
			return reasons, count, decodeErr
		}
		var oid asn1.ObjectIdentifier
		extRest, err := asn1.Unmarshal(ext.Bytes, &oid)
		if err != nil || !oid.Equal(oidCRLReason) {
			continue
		}
		count++
		// Skip optional critical BOOLEAN to reach the OCTET STRING extnValue.
		var next asn1.RawValue
		extRest, err = asn1.Unmarshal(extRest, &next)
		if err != nil {
			decodeErr = true
			continue
		}
		var extnValue []byte
		if next.Tag == asn1.TagOctetString {
			extnValue = next.Bytes
		} else {
			var octet asn1.RawValue
			if _, e := asn1.Unmarshal(extRest, &octet); e != nil || octet.Tag != asn1.TagOctetString {
				decodeErr = true
				continue
			}
			extnValue = octet.Bytes
		}
		var reasonCode asn1.Enumerated
		if _, e := asn1.Unmarshal(extnValue, &reasonCode); e == nil {
			reasons = append(reasons, int(reasonCode))
		} else {
			decodeErr = true
		}
	}
	return reasons, count, decodeErr
}

// rewrapBodyAsSequence re-wraps the raw content bytes of an IMPLICIT-tagged
// body CHOICE (where the SEQUENCE outer tag was replaced by the CHOICE tag)
// back into a UNIVERSAL SEQUENCE so it can be decoded as
// []cmp.CertReqMessage.
func rewrapBodyAsSequence(bodyBytes []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      bodyBytes,
	})
}

// certHashSHA256 returns the SHA-256 digest of certDER.
// This is the default certHash algorithm for RSA/ECDSA certificates
// (RFC 9481 §2 / RFC 9480 §2.10).
func certHashSHA256(certDER []byte) []byte {
	h := sha256.Sum256(certDER)
	return h[:]
}

// computeCertHash computes the certHash over certDER using the algorithm
// indicated by hashAlgOID. When hashAlgOID is nil/empty, the hash is chosen
// based on the issued certificate's signature algorithm per RFC 9481 §3.3:
//
//   - ECDSA-with-SHA384 / RSA-PSS-SHA384-issued → SHA-384
//   - ECDSA-with-SHA512 / RSA-PSS-SHA512-issued → SHA-512
//   - Ed25519-issued                            → SHA-512 (RFC 9481 §3.3
//     restricts EdDSA to a 512-bit certHash)
//   - everything else                           → SHA-256
//
// Per RFC 9481 §3 SHA-1 is deprecated for digital signatures and is no longer
// accepted, so we omit the id-sha1 OID branch.
//
// Supported hashAlg OIDs:
//   - 2.16.840.1.101.3.4.2.1  SHA-256
//   - 2.16.840.1.101.3.4.2.2  SHA-384
//   - 2.16.840.1.101.3.4.2.3  SHA-512
func computeCertHash(certDER []byte, hashAlgOID asn1.ObjectIdentifier) ([]byte, error) {
	if len(hashAlgOID) == 0 {
		return defaultCertHash(certDER)
	}

	switch hashAlgOID.String() {
	case "2.16.840.1.101.3.4.2.1": // id-sha256
		h := sha256.Sum256(certDER)
		return h[:], nil
	case "2.16.840.1.101.3.4.2.2": // id-sha384
		h := sha512.Sum384(certDER)
		return h[:], nil
	case "2.16.840.1.101.3.4.2.3": // id-sha512
		h := sha512.Sum512(certDER)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported certHash algorithm OID %s", hashAlgOID)
	}
}

// defaultCertHash picks the certHash algorithm per RFC 9481 §3.3 when the
// CertStatus does not include an explicit hashAlg [0] field. The rule keys
// the digest off the certificate's own signatureAlgorithm so an EE that
// follows the defaulting rule for a SHA-384-signed ECDSA cert gets the same
// expected hash as the server.
func defaultCertHash(certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		// If the certificate is unparseable, fall back to SHA-256 — the
		// historical default — instead of dropping the certConf entirely.
		h := sha256.Sum256(certDER)
		return h[:], nil
	}

	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA384,
		x509.SHA384WithRSA,
		x509.SHA384WithRSAPSS:
		h := sha512.Sum384(certDER)
		return h[:], nil
	case x509.ECDSAWithSHA512,
		x509.SHA512WithRSA,
		x509.SHA512WithRSAPSS,
		x509.PureEd25519:
		h := sha512.Sum512(certDER)
		return h[:], nil
	default:
		h := sha256.Sum256(certDER)
		return h[:], nil
	}
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
func nullDNGeneralName() asn1.RawValue {
	name := struct {
		RDNSequence pkix.RDNSequence
	}{RDNSequence: pkix.RDNSequence{}}
	der, _ := asn1.MarshalWithParams(name, "tag:4,optional")
	return asn1.RawValue{FullBytes: der}
}

// defaultSenderGeneralName returns the NULL-DN GeneralName used as the
// response PKIHeader Sender when the DMS has no protection certificate
// configured (RFC 9483 §3.1 line 713).
func defaultSenderGeneralName() asn1.RawValue {
	return nullDNGeneralName()
}

// defaultRecipientGeneralName returns the NULL-DN GeneralName used as the
// response PKIHeader Recipient when the intended recipient cannot be derived
// from the incoming request (RFC 9483 §3.1 line 803).
func defaultRecipientGeneralName() asn1.RawValue {
	return nullDNGeneralName()
}

type firstCertReq struct {
	CertReqID    int
	SubjectDER   []byte
	PublicKeyDER []byte
	// CertReqDER is the DER encoding of the CertRequest SEQUENCE.
	// The POPO signature (RFC 4211 §4.1 clause 3) is computed over this value.
	CertReqDER []byte
	// POPORaw is the raw ASN.1 value of the ProofOfPossession CHOICE,
	// as decoded from the CertReqMsg following the CertRequest.
	POPORaw asn1.RawValue
	// OldCertID carries the RFC 4211 §6.2 id-regCtrl-oldCertID control from the
	// CertRequest's optional `controls` field, when present. For a KUR it names
	// the certificate being updated (CertId = issuer + serialNumber). nil when no
	// such control was supplied.
	OldCertID *oldCertID
	// RegToken carries the RFC 4211 §6.1 id-regCtrl-regToken value from the
	// CertRequest's controls, when present. "" when no such control was
	// supplied. Enforced one-time-use via storage.CMPTransactionRepo.HasSeenRegToken.
	RegToken string
	// Extensions holds the requested X.509 extensions from the CertTemplate
	// `extensions [9]` field (KeyUsage/ExtKeyUsage/SubjectAltName). Empty when
	// the template requested none. Carried into the synthesized CSR so the
	// issuance profile can honor them (RFC 4211 §5 / RFC 9483 §4.1).
	Extensions []pkix.Extension
	// ControlsDER is the raw DER of the CertRequest optional `controls` field
	// (RFC 4211 §5), i.e. everything following the CertTemplate inside the
	// CertRequest SEQUENCE. Empty when no controls were supplied. Used to
	// validate registration controls such as id-regCtrl-pkiPublicationInfo.
	ControlsDER []byte
	// RegInfoDER is the raw DER of the CertReqMsg optional `regInfo` field
	// (RFC 4211 §6 / §7): a SEQUENCE OF AttributeTypeAndValue carrying, e.g.,
	// id-regInfo-certReq (an RA-supplied alternate CertRequest). Empty when the
	// message carried no regInfo.
	RegInfoDER []byte
	// ForKGA marks an RFC 9483 §4.1.6 central key generation request: the
	// CertTemplate carries no usable public key (the publicKey field is either
	// absent, or present with a zero-length subjectPublicKey) and no POPO, so the
	// server generates the end-entity key pair and returns it in the response.
	ForKGA bool
	// KGAKeyAlgorithm is the public key algorithm hint from the CertTemplate's
	// publicKey.algorithm when a for_kga request supplied one (RSA or ECDSA); it
	// tells the server which key type to generate. UnknownPublicKeyAlgorithm when
	// the request omitted the publicKey field entirely.
	KGAKeyAlgorithm x509.PublicKeyAlgorithm
}

// oidSubjectAltNameExt is the X.509 SubjectAltName extension OID (RFC 5280
// §4.2.1.6).
var oidSubjectAltNameExt = asn1.ObjectIdentifier{2, 5, 29, 17}

// emptyRDNSequenceDER returns the DER of an empty RDNSequence (a zero-length
// SEQUENCE, 0x30 0x00) — the canonical NULL-DN subject used when a CMP
// CertTemplate omits the subject but supplies a SubjectAltName.
func emptyRDNSequenceDER() []byte {
	return []byte{0x30, 0x00}
}

// isEmptySubjectDER reports whether a decoded CertTemplate subject is absent or
// a NULL-DN: either no bytes at all, or an empty RDNSequence (0x30 0x00).
func isEmptySubjectDER(subjectDER []byte) bool {
	if len(subjectDER) == 0 {
		return true
	}
	if len(subjectDER) == 2 && subjectDER[0] == 0x30 && subjectDER[1] == 0x00 {
		return true
	}
	return false
}

// hasSubjectAltNameExtension reports whether the requested CertTemplate
// extensions include a SubjectAltName (RFC 5280 §4.2.1.6).
func hasSubjectAltNameExtension(exts []pkix.Extension) bool {
	for _, e := range exts {
		if e.Id.Equal(oidSubjectAltNameExt) {
			return true
		}
	}
	return false
}

// decodeFirstCertReq extracts the fields needed for enrollment from the first
// CertReqMessage using manual ASN.1 peeling compatible with OpenSSL CMP.
func decodeFirstCertReq(bodyBytes []byte) (*firstCertReq, error) {
	var crMsgsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgsSeq); err != nil {
		return nil, fmt.Errorf("CertReqMessages: %w", err)
	}

	var crMsg asn1.RawValue
	crMsgsRest, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg)
	if err != nil {
		return nil, fmt.Errorf("CertReqMsg: %w", err)
	}
	// RFC 9483 §4.1: exactly one CertReqMsg is allowed per ir/cr/kur.
	if len(crMsgsRest) > 0 {
		return nil, &certRequestRejection{
			CertReqID:   0,
			Reason:      "ir/cr/kur must contain exactly one CertReqMsg (RFC 9483 §4.1)",
			FailInfoBit: pkiFailureInfoBadRequest,
		}
	}

	var certReqSeq asn1.RawValue
	certReqMsgRest, err := asn1.Unmarshal(crMsg.Bytes, &certReqSeq)
	if err != nil {
		return nil, fmt.Errorf("CertRequest: %w", err)
	}

	// Try to decode the optional ProofOfPossession CHOICE that follows CertRequest.
	var popoRaw asn1.RawValue
	if len(certReqMsgRest) > 0 {
		// Peek at the first TLV; any parse error just means POPO is absent.
		if _, parseErr := asn1.Unmarshal(certReqMsgRest, &popoRaw); parseErr != nil {
			popoRaw = asn1.RawValue{} // reset on error
		}
	}

	var certReqIDRaw asn1.RawValue
	rest, err := asn1.Unmarshal(certReqSeq.Bytes, &certReqIDRaw)
	if err != nil {
		return nil, fmt.Errorf("certReqId: %w", err)
	}
	if certReqIDRaw.Tag != asn1.TagInteger || certReqIDRaw.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected INTEGER for certReqId, got class=%d tag=%d", certReqIDRaw.Class, certReqIDRaw.Tag)
	}

	var certReqID int
	if _, err := asn1.Unmarshal(certReqIDRaw.FullBytes, &certReqID); err != nil {
		return nil, fmt.Errorf("parse certReqId: %w", err)
	}
	// RFC 9483 §4.1: certReqId MUST be 0.
	if certReqID != 0 {
		return nil, &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("certReqId must be 0 (RFC 9483 §4.1), got %d", certReqID),
			FailInfoBit: pkiFailureInfoBadRequest,
		}
	}

	var certTemplate asn1.RawValue
	controlsRest, err := asn1.Unmarshal(rest, &certTemplate)
	if err != nil {
		return nil, fmt.Errorf("CertTemplate: %w", err)
	}
	if certTemplate.Tag != asn1.TagSequence || certTemplate.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected UNIVERSAL SEQUENCE for CertTemplate, got class=%d tag=%d", certTemplate.Class, certTemplate.Tag)
	}

	// Optional `controls` SEQUENCE follows the CertTemplate (RFC 4211 §5). We
	// only care about id-regCtrl-oldCertID (KUR cert-to-update reference) and
	// id-regCtrl-regToken (one-time-use enforcement); everything else is
	// ignored. A malformed controls block is non-fatal — it just yields neither.
	oldCID := parseOldCertIDControl(controlsRest)
	regToken := parseRegTokenControl(controlsRest)

	// regInfo (RFC 4211 §6): the CertReqMsg may carry a SEQUENCE OF
	// AttributeTypeAndValue after the CertRequest and optional POPO. POPO's
	// CHOICE alternatives are all context-tagged, so the first UNIVERSAL SEQUENCE
	// in the remainder is the regInfo. Captured raw for alt-CertReq validation.
	regInfoDER := findRegInfoDER(certReqMsgRest)

	var subjectDER []byte
	var publicKeyDER []byte
	var extensions []pkix.Extension
	// KGA (RFC 9483 §4.1.6) detection state: whether a publicKey field was
	// present at all, and whether it carried an empty subjectPublicKey (the
	// "generate this for me" signal), plus the algorithm hint if any.
	pubKeyPresent := false
	pubKeyEmpty := false
	kgaKeyAlg := x509.UnknownPublicKeyAlgorithm
	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, fmt.Errorf("CertTemplate field: %w", err)
		}

		switch {
		case field.Class == asn1.ClassContextSpecific && field.Tag == 5:
			subjectDER, err = normalizeSequenceDER(field.Bytes, "subject")
			if err != nil {
				return nil, err
			}
		case field.Class == asn1.ClassContextSpecific && field.Tag == 6:
			pubKeyPresent = true
			// The [6] content is a SubjectPublicKeyInfo body (algorithm ||
			// subjectPublicKey). A for_kga request sends the algorithm hint with a
			// zero-length subjectPublicKey; detect that and remember the key type.
			pubKeyEmpty, kgaKeyAlg = inspectKGATemplateKey(field.Bytes)
			publicKeyDER, err = wrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo")
			if err != nil {
				return nil, err
			}
		case field.Class == asn1.ClassContextSpecific && field.Tag == 9:
			// extensions [9] Extensions (RFC 4211 §5). The EE uses these to
			// request KeyUsage/ExtKeyUsage/SubjectAltName; carry them so the
			// synthesized CSR reflects the requested template and the issuance
			// profile can honor them. A malformed extensions block is non-fatal:
			// it just yields no extensions rather than aborting enrollment.
			extensions = parseCertTemplateExtensions(field.Bytes)
		}
	}

	if isEmptySubjectDER(subjectDER) {
		// RFC 9483 §4.1.1 permits a NULL-DN (empty) subject when a
		// SubjectAltName extension carries the identity. Reject only when there
		// is neither a subject nor a SAN; otherwise normalize the subject to a
		// valid empty RDNSequence so the synthesized CSR encodes a proper
		// NULL-DN and the service derives the device identity from the SAN.
		if !hasSubjectAltNameExtension(extensions) {
			return nil, &certRequestRejection{
				CertReqID:   certReqID,
				Reason:      "subject field is required in CertTemplate unless a SubjectAltName extension is present (RFC 9483 §4.1.1)",
				FailInfoBit: pkiFailureInfoBadCertTemplate,
			}
		}
		subjectDER = emptyRDNSequenceDER()
	}
	// RFC 9483 §4.1.6 central key generation: the request deliberately omits a
	// usable public key so the server generates the key pair. Recognise the two
	// wire shapes the profile permits — publicKey present with a zero-length
	// subjectPublicKey, or publicKey absent together with an absent POPO (a plain
	// malformed request that merely forgot the key still carries a POPO, so this
	// stays distinct from that error) — and defer key handling to the KGA path.
	forKGA := pubKeyEmpty || (!pubKeyPresent && len(popoRaw.FullBytes) == 0)
	if len(publicKeyDER) == 0 && !forKGA {
		return nil, &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      "publicKey field is required in CertTemplate (RFC 9483 §4.1.3)",
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		}
	}

	return &firstCertReq{
		CertReqID:       certReqID,
		SubjectDER:      subjectDER,
		PublicKeyDER:    publicKeyDER,
		CertReqDER:      certReqSeq.FullBytes,
		POPORaw:         popoRaw,
		OldCertID:       oldCID,
		RegToken:        regToken,
		Extensions:      extensions,
		ControlsDER:     controlsRest,
		RegInfoDER:      regInfoDER,
		ForKGA:          forKGA,
		KGAKeyAlgorithm: kgaKeyAlg,
	}, nil
}

// inspectKGATemplateKey examines the body of a CertTemplate publicKey [6] field
// (a SubjectPublicKeyInfo: algorithm AlgorithmIdentifier, subjectPublicKey BIT
// STRING). It reports whether the subjectPublicKey is empty — the RFC 9483
// §4.1.6 "generate this key for me" signal — and, when it can, the public key
// algorithm named by the AlgorithmIdentifier (so the server knows which key
// type to generate). A parse failure yields (false, Unknown): treat it as a
// normal (non-empty) key and let downstream validation handle malformations.
func inspectKGATemplateKey(spkiBody []byte) (empty bool, alg x509.PublicKeyAlgorithm) {
	var algID asn1.RawValue
	rest, err := asn1.Unmarshal(spkiBody, &algID)
	if err != nil {
		return false, x509.UnknownPublicKeyAlgorithm
	}
	var subjectPublicKey asn1.BitString
	if _, err := asn1.Unmarshal(rest, &subjectPublicKey); err != nil {
		return false, x509.UnknownPublicKeyAlgorithm
	}
	if subjectPublicKey.BitLength != 0 {
		return false, x509.UnknownPublicKeyAlgorithm
	}
	// Empty key ⇒ for_kga. Resolve the algorithm OID for the key-type hint.
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(algID.Bytes, &oid); err != nil {
		return true, x509.UnknownPublicKeyAlgorithm
	}
	switch {
	case oid.Equal(oidRSAEncryption):
		return true, x509.RSA
	case oid.Equal(oidECPublicKey):
		return true, x509.ECDSA
	default:
		return true, x509.UnknownPublicKeyAlgorithm
	}
}

// parseCertTemplateExtensions decodes the content of a CertTemplate `extensions
// [9]` field (RFC 4211 §5). The [9] tag is IMPLICIT over Extensions ::=
// SEQUENCE OF Extension, so contentDER is the concatenation of Extension TLVs.
// A parse error stops decoding and returns whatever was decoded so far — the
// extensions are advisory (the issuance profile decides what to honor), so a
// malformed trailer must not fail the enrollment.
func parseCertTemplateExtensions(contentDER []byte) []pkix.Extension {
	var exts []pkix.Extension
	rest := contentDER
	for len(rest) > 0 {
		var ext pkix.Extension
		var err error
		rest, err = asn1.Unmarshal(rest, &ext)
		if err != nil {
			return exts
		}
		exts = append(exts, ext)
	}
	return exts
}

// RFC 4211 registration control / registration info OIDs.
var (
	// id-regCtrl-pkiPublicationInfo (1.3.6.1.5.5.7.5.1.3): asks the CA to
	// publish (or not publish) the issued certificate (RFC 4211 §6.3).
	oidRegCtrlPKIPublicationInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 3}
	// id-regInfo-certReq (1.3.6.1.5.5.7.5.2.2): an RA-supplied alternate
	// CertRequest carried in the CertReqMsg regInfo (RFC 4211 §7.2).
	oidRegInfoCertReq = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 2, 2}
)

// findRegInfoDER extracts the CertReqMsg `regInfo` field from the bytes that
// follow the CertRequest inside a CertReqMsg. That remainder is [ POPO? regInfo? ];
// every ProofOfPossession CHOICE alternative is context-tagged, so the first
// UNIVERSAL SEQUENCE encountered is the regInfo (SEQUENCE OF AttributeTypeAndValue).
// Returns nil when no regInfo is present.
func findRegInfoDER(afterCertReq []byte) []byte {
	scan := afterCertReq
	for len(scan) > 0 {
		var tlv asn1.RawValue
		rest, err := asn1.Unmarshal(scan, &tlv)
		if err != nil {
			return nil
		}
		if tlv.Class == asn1.ClassUniversal && tlv.Tag == asn1.TagSequence {
			return tlv.FullBytes
		}
		scan = rest
	}
	return nil
}

// validatePKIPublicationInfoControls enforces the structural rules of the
// id-regCtrl-pkiPublicationInfo control (RFC 4211 §6.3) when present in a
// CertRequest's `controls`. It only inspects that one control OID; oldCertID
// and regToken are handled by their own dedicated parse/validate functions
// (see parseOldCertIDControl, parseRegTokenControl / HasSeenRegToken), and
// authenticator is not validated at all — see the comment in handleEnrollment
// (cmp_enrollment.go) explaining why that one needs a new DMS config surface.
//
//	PKIPublicationInfo ::= SEQUENCE {
//	    action    INTEGER { dontPublish(0), pleasePublish(1) },
//	    pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
//	SinglePubInfo ::= SEQUENCE {
//	    pubMethod   INTEGER { dontCare(0), x500(1), web(2), ldap(3) },
//	    pubLocation GeneralName OPTIONAL }
//
// Rejections (badDataFormat):
//   - action outside {dontPublish, pleasePublish};
//   - dontPublish carrying any pubInfos (RFC 4211: none may be present);
//   - a pubMethod outside {dontCare, x500, web, ldap};
//   - pleasePublish with a concrete method (x500/web/ldap) but no pubLocation.
func validatePKIPublicationInfoControls(certReqID int, controlsDER []byte) *certRequestRejection {
	if len(controlsDER) == 0 {
		return nil
	}
	var controlsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(controlsDER, &controlsSeq); err != nil {
		return nil // malformed controls block: non-fatal, nothing to validate
	}
	if controlsSeq.Tag != asn1.TagSequence || controlsSeq.Class != asn1.ClassUniversal {
		return nil
	}

	reject := func(reason string) *certRequestRejection {
		return &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      reason,
			FailInfoBit: pkiFailureInfoBadDataFormat,
		}
	}

	rest := controlsSeq.Bytes
	for len(rest) > 0 {
		var attr asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil
		}
		// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
		var oid asn1.ObjectIdentifier
		valueRest, err := asn1.Unmarshal(attr.Bytes, &oid)
		if err != nil || !oid.Equal(oidRegCtrlPKIPublicationInfo) {
			continue
		}

		// value is a PKIPublicationInfo SEQUENCE.
		var pubInfo asn1.RawValue
		if _, err := asn1.Unmarshal(valueRest, &pubInfo); err != nil {
			return reject("malformed PKIPublicationInfo control (RFC 4211 §6.3)")
		}
		var action int
		pubInfosRest, err := asn1.Unmarshal(pubInfo.Bytes, &action)
		if err != nil {
			return reject("malformed PKIPublicationInfo action (RFC 4211 §6.3)")
		}
		const actionDontPublish, actionPleasePublish = 0, 1
		if action != actionDontPublish && action != actionPleasePublish {
			return reject(fmt.Sprintf("invalid PKIPublicationInfo action %d (RFC 4211 §6.3)", action))
		}

		hasPubInfos := len(pubInfosRest) > 0
		if action == actionDontPublish && hasPubInfos {
			return reject("PKIPublicationInfo dontPublish must not carry pubInfos (RFC 4211 §6.3)")
		}
		if !hasPubInfos {
			continue
		}

		// pleasePublish with pubInfos: validate each SinglePubInfo.
		var pubInfosSeq asn1.RawValue
		if _, err := asn1.Unmarshal(pubInfosRest, &pubInfosSeq); err != nil {
			return reject("malformed PKIPublicationInfo pubInfos (RFC 4211 §6.3)")
		}
		entries := pubInfosSeq.Bytes
		for len(entries) > 0 {
			var single asn1.RawValue
			entries, err = asn1.Unmarshal(entries, &single)
			if err != nil {
				return reject("malformed SinglePubInfo (RFC 4211 §6.3)")
			}
			var method int
			locRest, err := asn1.Unmarshal(single.Bytes, &method)
			if err != nil {
				return reject("malformed SinglePubInfo pubMethod (RFC 4211 §6.3)")
			}
			const methodDontCare = 0
			const methodLDAP = 3
			if method < methodDontCare || method > methodLDAP {
				return reject(fmt.Sprintf("invalid SinglePubInfo pubMethod %d (RFC 4211 §6.3)", method))
			}
			// A concrete publication method (x500/web/ldap) requires a location;
			// only dontCare may omit it.
			if method != methodDontCare && len(locRest) == 0 {
				return reject("PKIPublicationInfo pleasePublish requires a pubLocation (RFC 4211 §6.3)")
			}
		}
	}
	return nil
}

// findRegInfoCertReqDER scans a CertReqMsg's regInfo (SEQUENCE OF
// AttributeTypeAndValue) for the id-regInfo-certReq attribute (RFC 4211 §7.2)
// and returns the raw DER of its CertRequest value, or nil when absent.
func findRegInfoCertReqDER(regInfoDER []byte) []byte {
	if len(regInfoDER) == 0 {
		return nil
	}
	var regInfoSeq asn1.RawValue
	if _, err := asn1.Unmarshal(regInfoDER, &regInfoSeq); err != nil {
		return nil
	}
	if regInfoSeq.Tag != asn1.TagSequence || regInfoSeq.Class != asn1.ClassUniversal {
		return nil
	}

	rest := regInfoSeq.Bytes
	for len(rest) > 0 {
		var attr asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil
		}
		var oid asn1.ObjectIdentifier
		valueRest, err := asn1.Unmarshal(attr.Bytes, &oid)
		if err != nil || !oid.Equal(oidRegInfoCertReq) {
			continue
		}
		return valueRest
	}
	return nil
}

// validateAltCertReqPublicKey enforces RFC 4211 §7.2: when the regInfo carries
// an id-regInfo-certReq (an RA-supplied alternate CertRequest), its CertTemplate
// public key must match the public key of the primary CertRequest. A mismatch
// would invalidate the proof of possession, so it is rejected with
// badCertTemplate. Returns nil when no such control is present or the keys match.
func validateAltCertReqPublicKey(certReqID int, regInfoDER, mainPublicKeyDER []byte) *certRequestRejection {
	altCertReqDER := findRegInfoCertReqDER(regInfoDER)
	if len(altCertReqDER) == 0 {
		return nil
	}
	altPub, _ := parseAltCertRequestTemplate(altCertReqDER)
	if len(altPub) == 0 || len(mainPublicKeyDER) == 0 {
		return nil
	}
	if !bytes.Equal(altPub, mainPublicKeyDER) {
		return &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      "alternate CertRequest in regInfo carries a different public key than the primary request (RFC 4211 §7.2)",
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		}
	}
	return nil
}

// altCertReqExtensions returns the requested X.509 extensions carried by the
// regInfo's id-regInfo-certReq alternate CertRequest (RFC 4211 §7.2), or nil
// when no such control is present or it requests none. RFC 4211 §7.2 lets an RA
// modify the CertTemplate the CA should actually issue from while keeping the
// EE's original POPO valid (computed over the primary CertRequest); the
// extensions are the one part of that alternate template Lamassu currently
// honors — the public key is validated (not substituted) by
// validateAltCertReqPublicKey above.
func altCertReqExtensions(regInfoDER []byte) []pkix.Extension {
	altCertReqDER := findRegInfoCertReqDER(regInfoDER)
	if len(altCertReqDER) == 0 {
		return nil
	}
	_, exts := parseAltCertRequestTemplate(altCertReqDER)
	return exts
}

// parseAltCertRequestTemplate decodes a CertRequest SEQUENCE and returns its
// CertTemplate publicKey [6] (re-wrapped as a SubjectPublicKeyInfo SEQUENCE)
// and extensions [9], either of which is nil when absent/unparseable.
func parseAltCertRequestTemplate(certReqDER []byte) (publicKeyDER []byte, extensions []pkix.Extension) {
	var certReq asn1.RawValue
	if _, err := asn1.Unmarshal(certReqDER, &certReq); err != nil {
		return nil, nil
	}
	// CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate SEQUENCE, ... }
	inner := certReq.Bytes
	var certReqID asn1.RawValue
	inner, err := asn1.Unmarshal(inner, &certReqID)
	if err != nil {
		return nil, nil
	}
	var certTemplate asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &certTemplate); err != nil {
		return nil, nil
	}
	fields := certTemplate.Bytes
	for len(fields) > 0 {
		var field asn1.RawValue
		fields, err = asn1.Unmarshal(fields, &field)
		if err != nil {
			return publicKeyDER, extensions
		}
		switch {
		case field.Class == asn1.ClassContextSpecific && field.Tag == 6:
			if spki, e := wrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo"); e == nil {
				publicKeyDER = spki
			}
		case field.Class == asn1.ClassContextSpecific && field.Tag == 9:
			extensions = parseCertTemplateExtensions(field.Bytes)
		}
	}
	return publicKeyDER, extensions
}

// oidRegCtrlOldCertID is RFC 4211 §6.2 id-regCtrl-oldCertID (1.3.6.1.5.5.7.5.1.5).
var oidRegCtrlOldCertID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 5}

// parseOldCertIDControl scans an optional CertRequest `controls` field
// (SEQUENCE OF AttributeTypeAndValue) for id-regCtrl-oldCertID and decodes its
// CertId value { issuer GeneralName, serialNumber INTEGER }. It returns nil if
// controls is absent, the control is not present, or anything fails to parse —
// the control is optional, so a parse problem must not break enrollment.
// findControlValueDER scans a CertRequest's controls (RFC 4211 §5, SEQUENCE OF
// AttributeTypeAndValue) for the given control OID and returns its raw value
// DER, or nil when the controls block is absent/malformed or carries no
// attribute of that type.
func findControlValueDER(controlsDER []byte, oid asn1.ObjectIdentifier) []byte {
	if len(controlsDER) == 0 {
		return nil
	}
	var controlsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(controlsDER, &controlsSeq); err != nil {
		return nil
	}
	if controlsSeq.Tag != asn1.TagSequence || controlsSeq.Class != asn1.ClassUniversal {
		return nil
	}

	rest := controlsSeq.Bytes
	for len(rest) > 0 {
		var attr asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil
		}
		// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
		var attrOID asn1.ObjectIdentifier
		valDER, err := asn1.Unmarshal(attr.Bytes, &attrOID)
		if err != nil || !attrOID.Equal(oid) {
			continue
		}
		return valDER
	}
	return nil
}

func parseOldCertIDControl(controlsDER []byte) *oldCertID {
	valDER := findControlValueDER(controlsDER, oidRegCtrlOldCertID)
	if valDER == nil {
		return nil
	}
	// value is CertId ::= SEQUENCE { issuer GeneralName, serialNumber INTEGER }
	var certIDSeq asn1.RawValue
	if _, err := asn1.Unmarshal(valDER, &certIDSeq); err != nil {
		return nil
	}
	inner := certIDSeq.Bytes
	var issuer asn1.RawValue
	var err error
	inner, err = asn1.Unmarshal(inner, &issuer)
	if err != nil {
		return nil
	}
	// issuer GeneralName directoryName [4] EXPLICIT Name: issuer.Bytes is the
	// RDNSequence DER, directly comparable to x509.Certificate.RawIssuer.
	if issuer.Class != asn1.ClassContextSpecific || issuer.Tag != 4 {
		return nil
	}
	var serial *big.Int
	if _, err := asn1.Unmarshal(inner, &serial); err != nil {
		return nil
	}
	return &oldCertID{IssuerNameDER: issuer.Bytes, SerialNumber: serial}
}

// oidRegCtrlRegToken is RFC 4211 §6.1 id-regCtrl-regToken (1.3.6.1.5.5.7.5.1.1).
// RegToken ::= UTF8String — one-time information the CA uses to verify the
// requester's identity prior to issuance. Lamassu does not validate the value
// against any out-of-band secret (unlike the Authenticator control, this
// control's whole point is one-time USE, not matching a pre-shared answer);
// it only enforces that a given value is never accepted twice — see
// storage.CMPTransactionRepo.HasSeenRegToken.
var oidRegCtrlRegToken = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 1}

// parseRegTokenControl extracts the id-regCtrl-regToken value from a
// CertRequest's controls, or "" when absent/malformed.
func parseRegTokenControl(controlsDER []byte) string {
	valDER := findControlValueDER(controlsDER, oidRegCtrlRegToken)
	if valDER == nil {
		return ""
	}
	var token string
	if _, err := asn1.UnmarshalWithParams(valDER, &token, "utf8"); err != nil {
		return ""
	}
	return token
}

// oidRegCtrlAuthenticator is RFC 4211 §6.2 id-regCtrl-authenticator
// (1.3.6.1.5.5.7.5.1.2). Authenticator ::= UTF8String — a non-cryptographic,
// pre-shared answer (e.g. a security-question response) the CA can check on
// an ongoing basis, distinct from the one-time-use regToken above.
var oidRegCtrlAuthenticator = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 2}

// validateAuthenticatorControl enforces RFC 4211 §6.2 id-regCtrl-authenticator
// against the DMS's configured EnrollmentOptionsLWCRFC9483.ExpectedAuthenticator.
//
// When expected is "" (the DMS has not configured an expected answer — the
// default), the control is accepted unvalidated regardless of its value or
// absence: there is nothing to compare against. When expected is non-empty,
// a present Authenticator control whose value does not match is rejected with
// incorrectData (RFC 4211 §6.2 frames this as the requester's data being
// incorrect, not a malformed request); a malformed control value is rejected
// with badDataFormat. An absent control is not itself an error — whether the
// control is mandatory is a DMS policy decision outside this function's scope.
func validateAuthenticatorControl(certReqID int, controlsDER []byte, expected string) *certRequestRejection {
	if expected == "" {
		return nil
	}
	valDER := findControlValueDER(controlsDER, oidRegCtrlAuthenticator)
	if valDER == nil {
		return nil
	}
	var auth string
	if _, err := asn1.UnmarshalWithParams(valDER, &auth, "utf8"); err != nil {
		return &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("malformed Authenticator control (RFC 4211 §6.2): %v", err),
			FailInfoBit: pkiFailureInfoBadDataFormat,
		}
	}
	if auth != expected {
		return &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      "Authenticator control value does not match the expected answer (RFC 4211 §6.2)",
			FailInfoBit: pkiFailureInfoIncorrectData,
		}
	}
	return nil
}

func decodeRequestHeader(headerDER []byte) (requestPKIHeader, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(headerDER, &seq); err != nil {
		return requestPKIHeader{}, fmt.Errorf("PKIHeader: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return requestPKIHeader{}, fmt.Errorf("PKIHeader is not a SEQUENCE")
	}

	var header requestPKIHeader
	remaining := seq.Bytes

	var pvnoRaw asn1.RawValue
	var err error
	remaining, err = asn1.Unmarshal(remaining, &pvnoRaw)
	if err != nil {
		return requestPKIHeader{}, fmt.Errorf("pvno: %w", err)
	}
	if _, err := asn1.Unmarshal(pvnoRaw.FullBytes, &header.PVNO); err != nil {
		return requestPKIHeader{}, fmt.Errorf("parse pvno: %w", err)
	}

	remaining, err = asn1.Unmarshal(remaining, &header.Sender)
	if err != nil {
		return requestPKIHeader{}, fmt.Errorf("sender: %w", err)
	}

	remaining, err = asn1.Unmarshal(remaining, &header.Recipient)
	if err != nil {
		return requestPKIHeader{}, fmt.Errorf("recipient: %w", err)
	}

	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return requestPKIHeader{}, fmt.Errorf("optional header field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 0:
			// messageTime [0] EXPLICIT GeneralizedTime OPTIONAL (RFC 9483 §3.1).
			// field.Bytes is the inner GeneralizedTime TLV.
			var ts time.Time
			if _, e := asn1.Unmarshal(field.Bytes, &ts); e == nil {
				header.MessageTime = ts
			}
		case 1:
			// protectionAlg [1] AlgorithmIdentifier OPTIONAL.
			// Per RFC 4210 IMPLICIT TAGS, the [1] tag replaces the SEQUENCE tag
			// of AlgorithmIdentifier; field.Bytes therefore holds the SEQUENCE
			// content (algorithm OID + optional parameters). For PSS the
			// Parameters carry the hash OID and saltLength, so we capture the
			// full AlgorithmIdentifier rather than just the OID.
			var algOID asn1.ObjectIdentifier
			rest, e := asn1.Unmarshal(field.Bytes, &algOID)
			if e != nil {
				// Fall back to the older "[1] EXPLICIT SEQUENCE" decoding
				// (i.e. an extra SEQUENCE wrapper around AlgorithmIdentifier)
				// for samples produced by OpenSSL-era clients.
				var algSeq asn1.RawValue
				if _, e2 := asn1.Unmarshal(field.Bytes, &algSeq); e2 == nil {
					rest2, e3 := asn1.Unmarshal(algSeq.Bytes, &algOID)
					if e3 == nil {
						header.ProtectionAlg.Algorithm = algOID
						if len(rest2) > 0 {
							var params asn1.RawValue
							if _, e4 := asn1.Unmarshal(rest2, &params); e4 == nil {
								header.ProtectionAlg.Parameters = params
							}
						}
					}
				}
			} else {
				header.ProtectionAlg.Algorithm = algOID
				if len(rest) > 0 {
					var params asn1.RawValue
					if _, e2 := asn1.Unmarshal(rest, &params); e2 == nil {
						header.ProtectionAlg.Parameters = params
					}
				}
			}
		case 2:
			// senderKID [2] OCTET STRING OPTIONAL (RFC 9483 §3.1).
			// The CMP ASN.1 module declares IMPLICIT TAGS, but OpenSSL-derived
			// clients (and this server's own response builder) emit the [2]
			// wrapper EXPLICITLY around the inner OCTET STRING TLV — matching
			// the same convention used for transactionID/senderNonce. We try
			// the EXPLICIT form first and fall back to the literal-IMPLICIT
			// form so we interoperate with both wire conventions.
			var kid []byte
			if _, e := asn1.Unmarshal(field.Bytes, &kid); e == nil {
				header.SenderKID = kid
			} else {
				header.SenderKID = field.Bytes
			}
		case 4:
			header.TransactionID, err = decodeExplicitOctetString(field.Bytes, "transactionID")
		case 5:
			header.SenderNonce, err = decodeExplicitOctetString(field.Bytes, "senderNonce")
		case 6:
			header.RecipNonce, err = decodeExplicitOctetString(field.Bytes, "recipNonce")
		case 8:
			header.GeneralInfo, err = decodeGeneralInfo(field.Bytes)
		}
		if err != nil {
			return requestPKIHeader{}, err
		}
	}

	return header, nil
}

// decodeGeneralInfo parses the content bytes of a [8] EXPLICIT generalInfo field.
// generalInfo is SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue, where each
// InfoTypeAndValue is SEQUENCE { infoType OID, infoValue ANY OPTIONAL }.
// We return the raw InfoTypeAndValue entries for inspection.
func decodeGeneralInfo(bytes []byte) ([]asn1.RawValue, error) {
	// bytes is the content of [8] EXPLICIT, which is a SEQUENCE OF InfoTypeAndValue.
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(bytes, &seq); err != nil {
		return nil, fmt.Errorf("generalInfo SEQUENCE: %w", err)
	}
	var items []asn1.RawValue
	rest := seq.Bytes
	for len(rest) > 0 {
		var item asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &item)
		if err != nil {
			return nil, fmt.Errorf("generalInfo item: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

// hasImplicitConfirmOID reports whether any InfoTypeAndValue in the given
// generalInfo slice carries the id-it-implicitConfirm OID (1.3.6.1.5.5.7.4.13).
func hasImplicitConfirmOID(generalInfo []asn1.RawValue) bool {
	for _, item := range generalInfo {
		// Each item is a SEQUENCE { OID, ... }; we extract just the OID.
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(item.Bytes, &oid); err != nil {
			continue
		}
		if oid.Equal(oidImplicitConfirm) {
			return true
		}
	}
	return false
}

// extractOrigPKIMessage scans generalInfo for id-it-origPKIMessage
// (1.3.6.1.5.5.7.4.15) and, if present, returns the first embedded PKIMessage
// together with the protection AlgorithmIdentifier declared in its header.
//
// RFC 9483 §5.2.3 lets a PKI management entity (RA) forward the EE's original
// message to the CA under this OID. The value is OrigPKIMessageValue ::=
// PKIMessages (SEQUENCE OF PKIMessage); we return the first entry so the CA can
// verify the EE's own protection over what it actually signed. The boolean is
// false when no well-formed origPKIMessage is present.
func extractOrigPKIMessage(generalInfo []asn1.RawValue) (*rawPKIMessageFull, pkix.AlgorithmIdentifier, bool) {
	for _, item := range generalInfo {
		// item is InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }.
		var itav struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &itav); err != nil {
			continue
		}
		if !itav.OID.Equal(oidOrigPKIMessage) || len(itav.Value.Bytes) == 0 {
			continue
		}
		// itav.Value is the PKIMessages SEQUENCE OF; its content bytes begin with
		// the first PKIMessage TLV, which Unmarshal decodes here.
		var orig rawPKIMessageFull
		if _, err := asn1.Unmarshal(itav.Value.Bytes, &orig); err != nil {
			continue
		}
		origHeader, err := decodeRequestHeader(orig.Header.FullBytes)
		if err != nil {
			continue
		}
		return &orig, origHeader.ProtectionAlg, true
	}
	return nil, pkix.AlgorithmIdentifier{}, false
}

func decodeExplicitOctetString(der []byte, label string) ([]byte, error) {
	var value []byte
	if _, err := asn1.Unmarshal(der, &value); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return value, nil
}

func decodeCertConfStatuses(seqDER []byte) ([]certStatusASN1, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(seqDER, &outer); err != nil {
		return nil, fmt.Errorf("CertConfirmContent: %w", err)
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("CertConfirmContent is not a SEQUENCE")
	}

	var statuses []certStatusASN1
	remaining := outer.Bytes
	for len(remaining) > 0 {
		var certStatusSeq asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &certStatusSeq)
		if err != nil {
			return nil, fmt.Errorf("CertStatus: %w", err)
		}
		if certStatusSeq.Class != asn1.ClassUniversal || certStatusSeq.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("CertStatus is not a SEQUENCE")
		}

		var status certStatusASN1
		status.CertHash, err = findFirstOctetString(certStatusSeq.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("certHash: %w", err)
		}
		if len(status.CertHash) == 0 {
			return nil, fmt.Errorf("certHash missing")
		}

		// Parse certReqId (INTEGER) and the optional statusInfo (PKIStatusInfo
		// SEQUENCE) and hashAlg [0] from the CertStatus SEQUENCE fields. The
		// caller relies on CertReqID and StatusInfo for the structural
		// validation in handleCertConf (RFC 9483 §4.1.1).
		parseCertStatusFields(certStatusSeq.Bytes, &status)

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// parseCertStatusFields walks the fields of a CertStatus SEQUENCE content and
// fills CertReqID, StatusInfo and HashAlgOID on status.
//
//	CertStatus ::= SEQUENCE {
//	    certHash   OCTET STRING,
//	    certReqId  INTEGER,
//	    statusInfo PKIStatusInfo            OPTIONAL,
//	    hashAlg    [0] AlgorithmIdentifier  OPTIONAL }
func parseCertStatusFields(content []byte, status *certStatusASN1) {
	rest := content
	seenOctet := false
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return
		}
		switch {
		case field.Class == asn1.ClassContextSpecific && field.Tag == 0:
			// hashAlg [0] AlgorithmIdentifier. The CMP ASN.1 module uses
			// EXPLICIT tagging, so [0] wraps a full AlgorithmIdentifier
			// SEQUENCE { algorithm OID, parameters OPTIONAL }. Some encoders
			// emit it IMPLICIT (content starts directly with the OID). Handle
			// both: first try to decode an AlgorithmIdentifier SEQUENCE, then
			// fall back to a bare OID.
			var algID struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			if _, e := asn1.Unmarshal(field.Bytes, &algID); e == nil && len(algID.Algorithm) > 0 {
				status.HashAlgOID = algID.Algorithm
			} else {
				var oid asn1.ObjectIdentifier
				if _, e := asn1.Unmarshal(field.Bytes, &oid); e == nil {
					status.HashAlgOID = oid
				}
			}
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagOctetString && !seenOctet:
			// certHash — already captured via findFirstOctetString.
			seenOctet = true
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagInteger:
			var n int
			if _, e := asn1.Unmarshal(field.FullBytes, &n); e == nil {
				status.CertReqID = n
			}
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagSequence:
			// statusInfo PKIStatusInfo
			var si PKIStatusInfo
			if _, e := asn1.Unmarshal(field.FullBytes, &si); e == nil {
				status.StatusInfo = si
			}
		}
	}
}

// extractHashAlgFromCertStatus scans the inner fields of a CertStatus SEQUENCE
// for the optional hashAlg [0] IMPLICIT AlgorithmIdentifier. Returns the
// algorithm OID if found, or nil when absent (caller should default to SHA-256).
func extractHashAlgFromCertStatus(content []byte) asn1.ObjectIdentifier {
	rest := content
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil
		}
		// hashAlg is [0] IMPLICIT — context-specific, tag 0, constructed.
		if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			// Content is AlgorithmIdentifier: SEQUENCE { algorithm OID, ... }
			var oid asn1.ObjectIdentifier
			if _, e := asn1.Unmarshal(field.Bytes, &oid); e == nil {
				return oid
			}
			// Might be wrapped in SEQUENCE
			var inner asn1.RawValue
			if _, e := asn1.Unmarshal(field.Bytes, &inner); e == nil {
				if _, e2 := asn1.Unmarshal(inner.Bytes, &oid); e2 == nil {
					return oid
				}
			}
			return nil
		}
	}
	return nil
}

// maxOctetStringSearchDepth bounds findOctetStringInRaw's recursion. The
// structures this walks (CertStatus, PKIStatusInfo, ...) never legitimately
// nest more than a handful of levels deep; this input is fully attacker-
// controlled (certConf is unauthenticated at this point in parsing), so
// without a limit a pathologically nested SEQUENCE-of-SEQUENCE payload could
// recurse until it hits Go's stack limit and crashes the process with a
// non-recoverable fatal error.
const maxOctetStringSearchDepth = 32

func findFirstOctetString(der []byte) ([]byte, error) {
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(der, &root); err != nil {
		return nil, err
	}
	return findOctetStringInRaw(root, 0)
}

func findOctetStringInRaw(rv asn1.RawValue, depth int) ([]byte, error) {
	if depth > maxOctetStringSearchDepth {
		return nil, fmt.Errorf("ASN.1 structure nested too deeply (> %d levels)", maxOctetStringSearchDepth)
	}
	if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString {
		var out []byte
		if _, err := asn1.Unmarshal(rv.FullBytes, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if !rv.IsCompound {
		return nil, nil
	}

	remaining := rv.Bytes
	for len(remaining) > 0 {
		var child asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &child)
		if err != nil {
			return nil, err
		}
		found, err := findOctetStringInRaw(child, depth+1)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			return found, nil
		}
	}
	return nil, nil
}

// buildSyntheticCSR constructs a *x509.CertificateRequest from the Subject and
// SubjectPublicKeyInfo carried in a CMP CertTemplate (RFC 4211 §5).
//
// Because POPO is handled at the CMP layer (not inside the CSR), the resulting
// CSR has a dummy 1-byte zero signature. Set VerifyCSRSignature=false in the
// DMS EnrollmentSettings when using CMP to bypass csr.CheckSignature().
func buildSyntheticCSR(subjectDER, spkiDER []byte, extensions []pkix.Extension) (*x509.CertificateRequest, error) {
	// Parse public key to determine signature algorithm.
	pubKey, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Select a signature algorithm OID compatible with the key type.
	var sigAlgOID asn1.ObjectIdentifier
	switch pubKey.(type) {
	case *rsa.PublicKey:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // SHA256WithRSA
	case *ecdsa.PublicKey:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // ECDSAWithSHA256
	default:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // fallback RSA
	}

	// Assemble the CertificationRequestInfo attributes field ([0] IMPLICIT SET
	// OF Attribute). It is REQUIRED by Go's x509.ParseCertificateRequest even
	// when empty; omitting the tag causes "sequence truncated".
	//
	// The requested CertTemplate extensions (KeyUsage/ExtKeyUsage/SAN) MUST be
	// carried inside the DER via a PKCS#9 extensionRequest attribute — NOT just
	// attached to the parsed Go struct — because the CA client re-serializes the
	// CSR from its .Raw bytes over HTTP, which would drop struct-only fields.
	attrsContent, err := marshalExtensionRequestAttrs(extensions)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR attributes: %w", err)
	}
	attrsField, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrsContent,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal attrs field: %w", err)
	}
	type pkcs10CRI struct {
		Version int
		Subject asn1.RawValue
		SPKInfo asn1.RawValue
		Attrs   asn1.RawValue
	}
	criDER, err := asn1.Marshal(pkcs10CRI{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: subjectDER},
		SPKInfo: asn1.RawValue{FullBytes: spkiDER},
		Attrs:   asn1.RawValue{FullBytes: attrsField},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal CRI: %w", err)
	}

	// Assemble CertificationRequest with dummy signature.
	sigAlgDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: sigAlgOID})
	if err != nil {
		return nil, fmt.Errorf("marshal SigAlg: %w", err)
	}

	type pkcs10CSR struct {
		CRI    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	csrDER, err := asn1.Marshal(pkcs10CSR{
		CRI:    asn1.RawValue{FullBytes: criDER},
		SigAlg: asn1.RawValue{FullBytes: sigAlgDER},
		Sig:    asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal CSR DER: %w", err)
	}

	// Parse into *x509.CertificateRequest to populate all exported fields.
	// x509.ParseCertificateRequest reads the extensionRequest attribute we
	// embedded above into csr.Extensions, so the requested extensions survive
	// the CA client's .Raw-based re-serialization. What actually lands on the
	// issued cert is still gated by the issuance profile's Honor* flags.
	return x509.ParseCertificateRequest(csrDER)
}

// oidExtensionRequest is the PKCS#9 extensionRequest attribute type
// (1.2.840.113549.1.9.14, RFC 2985 §5.4.2) used to carry requested X.509
// extensions inside a PKCS#10 CertificationRequest.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// marshalExtensionRequestAttrs returns the DER content of a CSR's attributes
// SET OF Attribute. When exts is empty it returns nil (an empty attributes
// set). Otherwise it emits a single extensionRequest attribute whose value is
// the SEQUENCE OF Extension, so x509.ParseCertificateRequest surfaces them on
// CertificateRequest.Extensions and they persist through DER re-serialization.
func marshalExtensionRequestAttrs(exts []pkix.Extension) ([]byte, error) {
	if len(exts) == 0 {
		return nil, nil
	}
	// Extensions ::= SEQUENCE OF Extension
	extsSeqDER, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions sequence: %w", err)
	}
	// AttributeValue SET OF { Extensions }
	valuesSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: extsSeqDER,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal attribute values set: %w", err)
	}
	// Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }
	type pkcs10Attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}
	return asn1.Marshal(pkcs10Attribute{
		Type:   oidExtensionRequest,
		Values: asn1.RawValue{FullBytes: valuesSetDER},
	})
}
