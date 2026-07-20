package cmp

import (
	"encoding/asn1"
	"fmt"
)

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
func MarshalEncryptedKeyChoice(envelopedDataDER []byte) ([]byte, error) {
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
func MarshalCertOrEncCert(certDER []byte) ([]byte, error) {
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
func MarshalCertOrEncCertEncrypted(envelopedDataDER []byte) ([]byte, error) {
	encKeyChoice, err := MarshalEncryptedKeyChoice(envelopedDataDER)
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
func MarshalCertifiedKeyPair(certOrEncCertDER []byte) ([]byte, error) {
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
type CertRequestRejection struct {
	CertReqID   int
	Reason      string
	FailInfoBit int
}

func (e *CertRequestRejection) Error() string { return e.Reason }

// marshalCertRepRejectionBody assembles a CertRepMessage with a single
// CertResponse whose status is rejection. Used for cert-request-level failures
// (bad certReqId, missing subject, bad POP, etc.) where RFC 9483 §4.1 requires
// an ip/cp response body rather than an error body.
func MarshalCertRepRejectionBody(certReqID int, reason string, failInfoBit int) ([]byte, error) {
	certResp := ServerCertResponse{
		CertReqID: certReqID,
		Status: PKIStatusInfo{
			Status: PKIStatus(PKIStatusRejection),
			StatusString: PKIFreeText{
				asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(reason)},
			},
			FailInfo: EncodePKIFailureInfo([]int{failInfoBit}),
		},
	}
	msg := ServerCertRepMessage{Responses: []ServerCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalCertRepBody assembles the raw CertRepMessage DER. The PKIBody
// context-specific wrapper is added by sendRawBody.
// certReqID is the certReqId from the corresponding CertRequest.
// certDER is the DER of the issued certificate.
func MarshalCertRepBody(bodyTag, certReqID int, certDER []byte) ([]byte, error) {
	return MarshalCertRepBodyWithStatus(bodyTag, certReqID, int(PKIStatus(0)), certDER)
}

// marshalCertRepBodyWithStatus is marshalCertRepBody with an explicit
// PKIStatus. RFC 4210 §5.2.3 allows a successful CertResponse to carry either
// accepted (0) or grantedWithMods (1); the latter signals the issued
// certificate differs from what the request asked for (e.g. the CA dropped an
// unrecognized/invalid requested extension per RFC 9483 §5).
func MarshalCertRepBodyWithStatus(bodyTag, certReqID, statusCode int, certDER []byte) ([]byte, error) {
	_ = bodyTag
	certOrEncCert, err := MarshalCertOrEncCert(certDER)
	if err != nil {
		return nil, err
	}
	ckpDER, err := MarshalCertifiedKeyPair(certOrEncCert)
	if err != nil {
		return nil, err
	}
	certResp := ServerCertResponse{
		CertReqID:        certReqID,
		Status:           PKIStatusInfo{Status: PKIStatus(statusCode)},
		CertifiedKeyPair: asn1.RawValue{FullBytes: ckpDER},
	}
	msg := ServerCertRepMessage{Responses: []ServerCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalCertRepBodyEncrypted is marshalCertRepBodyWithStatus for the encrCert
// proof-of-possession method: the CertifiedKeyPair's certOrEncCert carries the
// encryptedCert alternative (envelopedDataDER, a CMS EnvelopedData whose
// content is the raw issued-certificate DER) instead of a plain certificate.
func MarshalCertRepBodyEncrypted(certReqID, statusCode int, envelopedDataDER []byte) ([]byte, error) {
	certOrEncCert, err := MarshalCertOrEncCertEncrypted(envelopedDataDER)
	if err != nil {
		return nil, err
	}
	ckpDER, err := MarshalCertifiedKeyPair(certOrEncCert)
	if err != nil {
		return nil, err
	}
	certResp := ServerCertResponse{
		CertReqID:        certReqID,
		Status:           PKIStatusInfo{Status: PKIStatus(statusCode)},
		CertifiedKeyPair: asn1.RawValue{FullBytes: ckpDER},
	}
	msg := ServerCertRepMessage{Responses: []ServerCertResponse{certResp}}
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
func MarshalKGACertifiedKeyPair(certOrEncCertDER, envelopedDataDER []byte) ([]byte, error) {
	encKeyChoice, err := MarshalEncryptedKeyChoice(envelopedDataDER)
	if err != nil {
		return nil, err
	}

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
// EnvelopedData produced by the backend KGA response builder.
func MarshalKGACertRepBody(certReqID, statusCode int, certDER, envelopedDataDER []byte) ([]byte, error) {
	certOrEncCert, err := MarshalCertOrEncCert(certDER)
	if err != nil {
		return nil, err
	}
	ckpDER, err := MarshalKGACertifiedKeyPair(certOrEncCert, envelopedDataDER)
	if err != nil {
		return nil, err
	}
	certResp := ServerCertResponse{
		CertReqID:        certReqID,
		Status:           PKIStatusInfo{Status: PKIStatus(statusCode)},
		CertifiedKeyPair: asn1.RawValue{FullBytes: ckpDER},
	}
	msg := ServerCertRepMessage{Responses: []ServerCertResponse{certResp}}
	return asn1.Marshal(msg)
}

// marshalPKIConfBody produces the raw body payload for pkiConf.
func MarshalPKIConfBody() ([]byte, error) {
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
func MarshalCertRepWaitingBody(certReqID int) ([]byte, error) {
	certResp := ServerCertResponse{
		CertReqID: certReqID,
		Status:    PKIStatusInfo{Status: PKIStatus(PKIStatusWaiting)},
	}
	msg := ServerCertRepMessage{Responses: []ServerCertResponse{certResp}}
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
type PollRepEntry struct {
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
func MarshalPollRepBody(certReqID, checkAfterSeconds int) ([]byte, error) {
	return asn1.Marshal([]PollRepEntry{
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
func DecodePollReqContent(bodyBytes []byte) (int, error) {
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
func MarshalErrorBody(status PKIStatus, reason string, failInfoBits ...int) ([]byte, error) {
	errMsg := ErrorMsgContent{
		PKIStatusInfo: PKIStatusInfo{
			Status: status,
			StatusString: PKIFreeText{
				asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(reason)},
			},
			FailInfo: EncodePKIFailureInfo(failInfoBits),
		},
	}
	return asn1.Marshal(errMsg)
}

// encodePKIFailureInfo packs the given bit positions (RFC 4210 §5.1.3) into a
// DER-encodable BIT STRING. An empty input returns the zero value, which
// asn1:"optional,omitempty" elides from the wire.
func EncodePKIFailureInfo(bits []int) asn1.BitString {
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
func MarshalRevRepBody(status PKIStatus, statusText string, failInfoBits ...int) ([]byte, error) {
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
		info.FailInfo = EncodePKIFailureInfo(failInfoBits)
	}
	return asn1.Marshal(revRepContent{
		Status: []PKIStatusInfo{info},
	})
}
