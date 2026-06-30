package controllers

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// CMP PKIBody CHOICE tag numbers (RFC 4210 §5.1.2 / RFC 9480).
const (
	cmpBodyTagIR       = 0  // ir  – Initialization Request
	cmpBodyTagIP       = 1  // ip  – Initialization Response
	cmpBodyTagCR       = 2  // cr  – Certificate Request
	cmpBodyTagCP       = 3  // cp  – Certificate Response
	cmpBodyTagKUR      = 7  // kur – Key Update Request
	cmpBodyTagKUP      = 8  // kup – Key Update Response
	cmpBodyTagRR       = 11 // rr  – Revocation Request
	cmpBodyTagRP       = 12 // rp  – Revocation Response
	cmpBodyTagCertConf = 24 // certConf – Certificate Confirmation
	cmpBodyTagPKIConf  = 19 // pkiConf  – PKI Confirmation
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
	pkiFailureInfoBadAlg             = 0  // unrecognized or unsupported algorithm identifier
	pkiFailureInfoBadMessageCheck    = 1  // integrity check (e.g. signature) failed
	pkiFailureInfoBadRequest         = 2  // request not permitted / malformed for the server
	pkiFailureInfoBadTime            = 3  // messageTime not sufficiently close to system time
	pkiFailureInfoBadCertId          = 4  // no certificate could be found matching the request
	pkiFailureInfoBadDataFormat      = 5  // the data submitted has the wrong format
	pkiFailureInfoIncorrectData      = 7  // requester's data is incorrect (notary services)
	pkiFailureInfoBadPOP             = 9  // proof-of-possession failed
	pkiFailureInfoCertRevoked        = 10 // referenced/protection certificate is revoked
	pkiFailureInfoBadRecipientNonce  = 13 // recipNonce did not match the expected senderNonce
	pkiFailureInfoBadSenderNonce     = 18 // sender nonce missing or too short (RFC 9483 §3.5)
	pkiFailureInfoBadCertTemplate    = 19 // submitted CertTemplate is incomplete or invalid
	pkiFailureInfoSignerNotTrusted   = 20 // protection signer cert not trusted / no trust anchor (RFC 9483 §3.5)
	pkiFailureInfoTransactionIDInUse = 21 // transactionID collides with an in-flight one (RFC 9810 §3.1)
	pkiFailureInfoUnsupportedVersion = 22 // pvno not understood (RFC 9810 §7 / RFC 9483 §3.5)
	pkiFailureInfoNotAuthorized      = 23 // sender not authorized for the request (RFC 9810 §3.1)
	pkiFailureInfoSystemFailure      = 25
	// pkiStatusWaiting is RFC 4210 §5.2.3 PKIStatus value 3, sent on the initial
	// ip/cp/kup response in async-issuance mode to tell the EE that the
	// certificate is not yet available and it should poll for it later.
	pkiStatusWaiting = 3
)

// oidImplicitConfirm is id-it-implicitConfirm (1.3.6.1.5.5.7.4.13).
// When present in the request PKIHeader generalInfo field, the EE signals that
// it supports implicit certificate confirmation per RFC 4210 §5.3.2.
var oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}

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

// marshalCertOrEncCert encodes a certificate DER as the `certificate`
// alternative of the CertOrEncCert CHOICE.
//
//	CertOrEncCert ::= CHOICE {
//	    certificate   [0] CMPCertificate,
//	    encryptedCert [1] EncryptedValue }
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
		Status:           PKIStatusInfo{Status: PKIStatus(0)}, // accepted
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
func marshalRevRepBody(status PKIStatus) ([]byte, error) {
	type revRepContent struct {
		Status []PKIStatusInfo
	}
	return asn1.Marshal(revRepContent{
		Status: []PKIStatusInfo{
			{Status: status},
		},
	})
}

// decodeRevReqContent parses the RevReqContent from an rr body.
// RevReqContent ::= SEQUENCE OF RevDetails
//
//	RevDetails    ::= SEQUENCE {
//	    certDetails     CertTemplate,
//	    crlEntryDetails Extensions OPTIONAL }
//
// We extract the serialNumber ([1] context-specific INTEGER in CertTemplate)
// and the optional CRL reason from crlEntryDetails.
func decodeRevReqContent(bodyBytes []byte) (serialNumber []byte, reason int, err error) {
	// bodyBytes is the content of [11] IMPLICIT — it holds a full
	// SEQUENCE OF RevDetails TLV (the outer SEQUENCE tag was replaced
	// by [11] in the PKIMessage, and asn1.Unmarshal puts the inner
	// content in Body.Bytes which IS the SEQUENCE TLV).
	var revDetailsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &revDetailsSeq); err != nil {
		return nil, 0, fmt.Errorf("RevReqContent: %w", err)
	}

	// First element is a RevDetails SEQUENCE.
	var revDetails asn1.RawValue
	if _, err := asn1.Unmarshal(revDetailsSeq.Bytes, &revDetails); err != nil {
		return nil, 0, fmt.Errorf("RevDetails: %w", err)
	}

	// RevDetails.certDetails is a CertTemplate SEQUENCE.
	var certTemplate asn1.RawValue
	crlExtRest, err := asn1.Unmarshal(revDetails.Bytes, &certTemplate)
	if err != nil {
		return nil, 0, fmt.Errorf("CertTemplate: %w", err)
	}

	// Walk CertTemplate fields looking for serialNumber [1] INTEGER.
	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, 0, fmt.Errorf("CertTemplate field: %w", err)
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 1 {
			// [1] is serialNumber — an INTEGER whose DER encoding is in field.Bytes.
			// Re-interpret as UNIVERSAL INTEGER to extract the bytes.
			var sn asn1.RawValue
			if _, e := asn1.Unmarshal(field.Bytes, &sn); e == nil && sn.Tag == asn1.TagInteger {
				serialNumber = sn.Bytes
			} else {
				// If the content is the raw integer octets directly (no tag),
				// use field.Bytes as-is.
				serialNumber = field.Bytes
			}
			// ASN.1 INTEGER prepends 0x00 when the high bit of the leading byte
			// would otherwise be 1 (which would mark it as negative). Lamassu's
			// certificate storage keys are big.Int-normalized hex (no leading
			// 0x00), so we must strip the padding byte here to make lookups match.
			if len(serialNumber) > 1 && serialNumber[0] == 0x00 {
				serialNumber = serialNumber[1:]
			}
		}
	}
	if len(serialNumber) == 0 {
		return nil, 0, fmt.Errorf("serialNumber [1] not found in CertTemplate")
	}

	// Try to extract CRL reason from crlEntryDetails (Extensions, OPTIONAL).
	// Extensions ::= SEQUENCE OF Extension
	// Extension  ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
	// CRL Reason OID = 2.5.29.21, extnValue wraps an ENUMERATED.
	reason = 0 // default: unspecified
	if len(crlExtRest) > 0 {
		reason = parseCRLReasonFromExtensions(crlExtRest)
	}
	return serialNumber, reason, nil
}

// parseCRLReasonFromExtensions scans an Extensions SEQUENCE for id-ce-CRLReasons
// (2.5.29.21) and returns the ENUMERATED reason code, or 0 if not found.
func parseCRLReasonFromExtensions(der []byte) int {
	var extsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &extsSeq); err != nil {
		return 0
	}
	remaining := extsSeq.Bytes
	oidCRLReason := asn1.ObjectIdentifier{2, 5, 29, 21}
	for len(remaining) > 0 {
		var ext asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &ext)
		if err != nil {
			return 0
		}
		// Each Extension is SEQUENCE { OID, BOOLEAN?, OCTET STRING }
		var oid asn1.ObjectIdentifier
		extRest, err := asn1.Unmarshal(ext.Bytes, &oid)
		if err != nil || !oid.Equal(oidCRLReason) {
			continue
		}
		// Skip optional critical BOOLEAN.
		var next asn1.RawValue
		extRest, err = asn1.Unmarshal(extRest, &next)
		if err != nil {
			continue
		}
		var extnValue []byte
		if next.Tag == asn1.TagOctetString {
			extnValue = next.Bytes
		} else {
			// Was critical BOOLEAN; next TLV is the OCTET STRING.
			var octet asn1.RawValue
			if _, e := asn1.Unmarshal(extRest, &octet); e != nil || octet.Tag != asn1.TagOctetString {
				continue
			}
			extnValue = octet.Bytes
		}
		// extnValue wraps an ENUMERATED.
		var reasonCode asn1.Enumerated
		if _, e := asn1.Unmarshal(extnValue, &reasonCode); e == nil {
			return int(reasonCode)
		}
	}
	return 0
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
