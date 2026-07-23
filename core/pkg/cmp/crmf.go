package cmp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type CertRequest struct {
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
	OldCertID *OldCertID
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
func EmptyRDNSequenceDER() []byte {
	return []byte{0x30, 0x00}
}

// isEmptySubjectDER reports whether a decoded CertTemplate subject is absent or
// a NULL-DN: either no bytes at all, or an empty RDNSequence (0x30 0x00).
func IsEmptySubjectDER(subjectDER []byte) bool {
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
func HasSubjectAltNameExtension(exts []pkix.Extension) bool {
	for _, e := range exts {
		if e.Id.Equal(oidSubjectAltNameExt) {
			return true
		}
	}
	return false
}

// decodeFirstCertReq extracts the fields needed for enrollment from the first
// CertReqMessage using manual ASN.1 peeling compatible with OpenSSL CMP.
func DecodeFirstCertReq(bodyBytes []byte) (*CertRequest, error) {
	var crMsgsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgsSeq); err != nil {
		return nil, fmt.Errorf("CertReqMessages: %w", err)
	}

	var crMsg asn1.RawValue
	crMsgsRest, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg)
	if err != nil {
		return nil, fmt.Errorf("CertReqMsg: %w", err)
	}

	if len(crMsgsRest) > 0 {
		return nil, &CertRequestRejection{
			CertReqID:   0,
			Reason:      "ir/cr/kur must contain exactly one CertReqMsg (RFC 9483 §4.1)",
			FailInfoBit: PKIFailureInfoBadRequest,
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

		if _, parseErr := asn1.Unmarshal(certReqMsgRest, &popoRaw); parseErr != nil {
			popoRaw = asn1.RawValue{}
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

	if certReqID != 0 {
		return nil, &CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("certReqId must be 0 (RFC 9483 §4.1), got %d", certReqID),
			FailInfoBit: PKIFailureInfoBadRequest,
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

	oldCID := parseOldCertIDControl(controlsRest)
	regToken := parseRegTokenControl(controlsRest)

	regInfoDER := findRegInfoDER(certReqMsgRest)

	var subjectDER []byte
	var publicKeyDER []byte
	var extensions []pkix.Extension

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

			pubKeyEmpty, kgaKeyAlg = InspectKGATemplateKey(field.Bytes)
			publicKeyDER, err = WrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo")
			if err != nil {
				return nil, err
			}
		case field.Class == asn1.ClassContextSpecific && field.Tag == 9:

			extensions = parseCertTemplateExtensions(field.Bytes)
		}
	}

	if IsEmptySubjectDER(subjectDER) {

		if !HasSubjectAltNameExtension(extensions) {
			return nil, &CertRequestRejection{
				CertReqID:   certReqID,
				Reason:      "subject field is required in CertTemplate unless a SubjectAltName extension is present (RFC 9483 §4.1.1)",
				FailInfoBit: PKIFailureInfoBadCertTemplate,
			}
		}
		subjectDER = EmptyRDNSequenceDER()
	}

	forKGA := pubKeyEmpty || (!pubKeyPresent && len(popoRaw.FullBytes) == 0)
	if len(publicKeyDER) == 0 && !forKGA {
		return nil, &CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      "publicKey field is required in CertTemplate (RFC 9483 §4.1.3)",
			FailInfoBit: PKIFailureInfoBadCertTemplate,
		}
	}

	return &CertRequest{
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
func InspectKGATemplateKey(spkiBody []byte) (empty bool, alg x509.PublicKeyAlgorithm) {
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
func ValidatePKIPublicationInfoControls(certReqID int, controlsDER []byte) *CertRequestRejection {
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

	reject := func(reason string) *CertRequestRejection {
		return &CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      reason,
			FailInfoBit: PKIFailureInfoBadDataFormat,
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
func ValidateAltCertReqPublicKey(certReqID int, regInfoDER, mainPublicKeyDER []byte) *CertRequestRejection {
	altCertReqDER := findRegInfoCertReqDER(regInfoDER)
	if len(altCertReqDER) == 0 {
		return nil
	}
	altPub, _ := parseAltCertRequestTemplate(altCertReqDER)
	if len(altPub) == 0 || len(mainPublicKeyDER) == 0 {
		return nil
	}
	if !bytes.Equal(altPub, mainPublicKeyDER) {
		return &CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      "alternate CertRequest in regInfo carries a different public key than the primary request (RFC 4211 §7.2)",
			FailInfoBit: PKIFailureInfoBadCertTemplate,
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
func AltCertReqExtensions(regInfoDER []byte) []pkix.Extension {
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
			if spki, e := WrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo"); e == nil {
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

func parseOldCertIDControl(controlsDER []byte) *OldCertID {
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

	if issuer.Class != asn1.ClassContextSpecific || issuer.Tag != 4 {
		return nil
	}
	var serial *big.Int
	if _, err := asn1.Unmarshal(inner, &serial); err != nil {
		return nil
	}
	return &OldCertID{IssuerNameDER: issuer.Bytes, SerialNumber: serial}
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
// HasAuthenticatorControl reports whether controlsDER carries an
// id-regCtrl-authenticator control at all, independent of whether the DMS has
// an ExpectedAuthenticator configured. Used by RFC011's per-DMS
// authenticator_control.mode (disabled/optional/required) to gate on presence
// rather than value.
func HasAuthenticatorControl(controlsDER []byte) bool {
	return findControlValueDER(controlsDER, oidRegCtrlAuthenticator) != nil
}

func ValidateAuthenticatorControl(certReqID int, controlsDER []byte, expected string) *CertRequestRejection {
	if expected == "" {
		return nil
	}
	valDER := findControlValueDER(controlsDER, oidRegCtrlAuthenticator)
	if valDER == nil {
		return nil
	}
	var auth string
	if _, err := asn1.UnmarshalWithParams(valDER, &auth, "utf8"); err != nil {
		return &CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("malformed Authenticator control (RFC 4211 §6.2): %v", err),
			FailInfoBit: PKIFailureInfoBadDataFormat,
		}
	}
	if auth != expected {
		return &CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      "Authenticator control value does not match the expected answer (RFC 4211 §6.2)",
			FailInfoBit: PKIFailureInfoIncorrectData,
		}
	}
	return nil
}
