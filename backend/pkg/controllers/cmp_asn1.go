package controllers

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"

	"github.com/zjj/gocmp/cmp"
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

	// pvnoCMP2000 is the protocol version for RFC 4210 (cmp2000 = 2).
	// Servers MUST default to pvno=2 per RFC 9480 §2.20.
	pvnoCMP2000 = 2

	// pkiStatusAccepted is RFC 4210 §5.2.3 PKIStatus value 0.
	pkiStatusAccepted = 0
	// pkiStatusRejection is RFC 4210 §5.2.3 PKIStatus value 2.
	pkiStatusRejection = 2
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
	oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}  // id-PasswordBasedMac  RFC 4210
	oidDHBasedMac       = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 30}  // id-DHBasedMac        RFC 4210
)

// hashFromSignatureAlgOID maps a signature algorithm OID to the hash function
// used to digest the signed data. Ed25519 returns crypto.Hash(0) because it
// hashes internally. Returns an error for unknown OIDs.
//
// Used for incoming request-protection verification and response algorithm
// selection.
func hashFromSignatureAlgOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch oid.String() {
	case "1.2.840.113549.1.1.5": // sha1WithRSAEncryption
		return crypto.SHA1, nil
	case "1.2.840.113549.1.1.11": // sha256WithRSAEncryption
		return crypto.SHA256, nil
	case "1.2.840.113549.1.1.12": // sha384WithRSAEncryption
		return crypto.SHA384, nil
	case "1.2.840.113549.1.1.13": // sha512WithRSAEncryption
		return crypto.SHA512, nil
	case "1.2.840.10045.4.3.1": // ecdsaWithSHA224
		return crypto.SHA224, nil
	case "1.2.840.10045.4.3.2": // ecdsaWithSHA256
		return crypto.SHA256, nil
	case "1.2.840.10045.4.3.3": // ecdsaWithSHA384
		return crypto.SHA384, nil
	case "1.2.840.10045.4.3.4": // ecdsaWithSHA512
		return crypto.SHA512, nil
	case "1.3.101.112": // id-Ed25519
		return crypto.Hash(0), nil
	default:
		return 0, fmt.Errorf("unsupported signature algorithm OID %s", oid)
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
// RFC 4210 uses DEFINITIONS IMPLICIT TAGS, so:
//   - protection [0] PKIProtection → EXPLICIT [0] BIT STRING (explicit per gocmp/OpenSSL convention)
//   - extraCerts [1] SEQUENCE OF  → IMPLICIT [1] (tag replaces SEQUENCE OF, no extra wrapper)
type rawPKIMessageFull struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,tag:1"`
}

type requestPKIHeader struct {
	PVNO             int
	Sender           asn1.RawValue
	Recipient        asn1.RawValue
	ProtectionAlgOID asn1.ObjectIdentifier // parsed from [1] protectionAlg; empty when absent
	TransactionID    []byte          `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce      []byte          `asn1:"optional,explicit,tag:5,omitempty"`
	RecipNonce       []byte          `asn1:"optional,explicit,tag:6,omitempty"`
	GeneralInfo      []asn1.RawValue // decoded from [8] EXPLICIT SEQUENCE; empty when absent

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
	StatusInfo cmp.PKIStatusInfo `asn1:"optional"`
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
	Status           cmp.PKIStatusInfo
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
		Status:           cmp.PKIStatusInfo{Status: cmp.PKIStatus(0)}, // accepted
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
		Status:    cmp.PKIStatusInfo{Status: cmp.PKIStatus(pkiStatusWaiting)},
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
// added by sendRawBody.
func marshalErrorBody(status cmp.PKIStatus, reason string) ([]byte, error) {
	errMsg := cmp.ErrorMsgContent{
		PKIStatusInfo: cmp.PKIStatusInfo{
			Status: status,
			StatusString: cmp.PKIFreeText{
				asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(reason)},
			},
		},
	}
	return asn1.Marshal(errMsg)
}

// marshalRevRepBody produces the raw RevRepContent DER for an rp (tag 12) body.
// RevRepContent ::= SEQUENCE { status SEQUENCE OF PKIStatusInfo, ... }
func marshalRevRepBody(status cmp.PKIStatus) ([]byte, error) {
	type revRepContent struct {
		Status []cmp.PKIStatusInfo
	}
	return asn1.Marshal(revRepContent{
		Status: []cmp.PKIStatusInfo{
			{Status: status},
		},
	})
}

// decodeRevReqContent parses the RevReqContent from an rr body.
// RevReqContent ::= SEQUENCE OF RevDetails
// RevDetails    ::= SEQUENCE {
//     certDetails     CertTemplate,
//     crlEntryDetails Extensions OPTIONAL }
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
// indicated by hashAlgOID. When hashAlgOID is nil/empty, SHA-256 is used
// per the default in RFC 9481 §3.3.
//
// Supported OIDs:
//   - 2.16.840.1.101.3.4.2.1  SHA-256 (default)
//   - 2.16.840.1.101.3.4.2.2  SHA-384
//   - 2.16.840.1.101.3.4.2.3  SHA-512
//   - 1.3.14.3.2.26           SHA-1 (legacy, accepted)
func computeCertHash(certDER []byte, hashAlgOID asn1.ObjectIdentifier) ([]byte, error) {
	if len(hashAlgOID) == 0 {
		h := sha256.Sum256(certDER)
		return h[:], nil
	}

	var hasher hash.Hash
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
	case "1.3.14.3.2.26": // id-sha1
		hasher = crypto.SHA1.New()
	default:
		return nil, fmt.Errorf("unsupported certHash algorithm OID %s", hashAlgOID)
	}

	hasher.Write(certDER)
	return hasher.Sum(nil), nil
}
