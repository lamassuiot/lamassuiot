package controllers

import (
	"crypto/sha256"
	"encoding/asn1"

	"github.com/zjj/gocmp/cmp"
)

// CMP PKIBody CHOICE tag numbers (RFC 4210 §5.1.2 / RFC 9480).
const (
	cmpBodyTagIR       = 0  // ir  – Initialization Request
	cmpBodyTagIP       = 1  // ip  – Initialization Response  (unused server-side)
	cmpBodyTagCR       = 2  // cr  – Certificate Request
	cmpBodyTagCP       = 3  // cp  – Certificate Response
	cmpBodyTagKUR      = 7  // kur – Key Update Request
	cmpBodyTagKUP      = 8  // kup – Key Update Response
	cmpBodyTagCertConf = 24 // certConf – Certificate Confirmation
	cmpBodyTagPKIConf  = 19 // pkiConf  – PKI Confirmation
	cmpBodyTagError    = 23 // error    – Error Message

	// pvnoCMP2000 is the protocol version for RFC 4210 (cmp2000 = 2).
	// Servers MUST default to pvno=2 per RFC 9480 §2.20.
	pvnoCMP2000 = 2
)

// oidImplicitConfirm is id-it-implicitConfirm (1.3.6.1.5.5.7.4.13).
// When present in the request PKIHeader generalInfo field, the EE signals that
// it supports implicit certificate confirmation per RFC 4210 §5.3.2.
var oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}

// rawPKIMessage captures the Header and Body of an incoming PKIMessage for
// body-tag dispatch. Protection and ExtraCerts are omitted here; use
// rawPKIMessageFull when those fields are needed.
type rawPKIMessage struct {
	Header asn1.RawValue
	Body   asn1.RawValue
}

// rawPKIMessageFull captures all four top-level fields of a PKIMessage so that
// the controller can verify incoming signature-based protection.
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
	TransactionID []byte          `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce   []byte          `asn1:"optional,explicit,tag:5,omitempty"`
	RecipNonce    []byte          `asn1:"optional,explicit,tag:6,omitempty"`
	GeneralInfo   []asn1.RawValue // decoded from [8] EXPLICIT SEQUENCE; empty when absent
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
// hashAlg is omitted; it is only required for EdDSA (RFC 9481 §3.3), which is
// out of scope for this initial implementation.
type certStatusASN1 struct {
	CertHash   []byte
	CertReqID  int
	StatusInfo cmp.PKIStatusInfo `asn1:"optional"`
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
