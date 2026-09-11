package cmp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ProofOfPossessionMode selects the CRMF ProofOfPossession alternative.
type ProofOfPossessionMode int

const (
	ProofOfPossessionNone ProofOfPossessionMode = iota
	ProofOfPossessionSignature
	ProofOfPossessionRAVerified
)

// EnrollmentRequestOptions describes one CRMF CertReqMsg used by ir, cr, or
// kur. Signer signs the CertRequest when ProofOfPossessionSignature is used.
type EnrollmentRequestOptions struct {
	CertReqID     int
	Subject       pkix.Name
	PublicKey     any
	Extensions    []pkix.Extension
	Proof         ProofOfPossessionMode
	Signer        crypto.Signer
	RegToken      string
	Authenticator string
	OldCertID     *OldCertID
	publicKeyDER  []byte
}

// KGAEnrollmentRequestOptions describes a central-key-generation enrollment
// request. KeyAlgorithm is encoded as an empty SubjectPublicKeyInfo so the
// server knows which kind of key to generate.
type KGAEnrollmentRequestOptions struct {
	CertReqID     int
	Subject       pkix.Name
	KeyAlgorithm  x509.PublicKeyAlgorithm
	Extensions    []pkix.Extension
	RegToken      string
	Authenticator string
	OldCertID     *OldCertID
}

// BuildKGAEnrollmentRequest creates an RFC 9483 central-key-generation CRMF
// request. Such a request carries an empty public key and no proof of possession.
func BuildKGAEnrollmentRequest(bodyType BodyType, options KGAEnrollmentRequestOptions) (EncodedBody, error) {
	spkiDER, err := marshalEmptySubjectPublicKeyInfo(options.KeyAlgorithm)
	if err != nil {
		return EncodedBody{}, err
	}
	return BuildEnrollmentRequest(bodyType, EnrollmentRequestOptions{
		CertReqID:     options.CertReqID,
		Subject:       options.Subject,
		Extensions:    options.Extensions,
		Proof:         ProofOfPossessionNone,
		RegToken:      options.RegToken,
		Authenticator: options.Authenticator,
		OldCertID:     options.OldCertID,
		publicKeyDER:  spkiDER,
	})
}

// BuildEnrollmentRequest creates the CRMF payload for an ir, cr, or kur body.
func BuildEnrollmentRequest(bodyType BodyType, options EnrollmentRequestOptions) (EncodedBody, error) {
	if bodyType != BodyIR && bodyType != BodyCR && bodyType != BodyKUR {
		return EncodedBody{}, fmt.Errorf("body type %d is not a CRMF enrollment request", bodyType)
	}
	certRequestDER, err := marshalCertRequest(options)
	if err != nil {
		return EncodedBody{}, err
	}
	parts := [][]byte{certRequestDER}
	switch options.Proof {
	case ProofOfPossessionNone:
	case ProofOfPossessionRAVerified:
		raVerified, err := marshalContext(0, false, nil)
		if err != nil {
			return EncodedBody{}, err
		}
		parts = append(parts, raVerified)
	case ProofOfPossessionSignature:
		if options.Signer == nil {
			return EncodedBody{}, fmt.Errorf("signature proof of possession requires a signer")
		}
		popo, err := marshalPOPOSigningKey(certRequestDER, options.Signer)
		if err != nil {
			return EncodedBody{}, err
		}
		parts = append(parts, popo)
	default:
		return EncodedBody{}, fmt.Errorf("unsupported proof-of-possession mode %d", options.Proof)
	}
	certReqMsg, err := marshalSequence(parts...)
	if err != nil {
		return EncodedBody{}, err
	}
	content, err := marshalSequence(certReqMsg)
	if err != nil {
		return EncodedBody{}, err
	}
	return EncodedBody{Type: bodyType, DER: content}, nil
}

func marshalCertRequest(options EnrollmentRequestOptions) ([]byte, error) {
	requestID, err := asn1.Marshal(options.CertReqID)
	if err != nil {
		return nil, err
	}
	var templateFields [][]byte
	if subject := options.Subject.ToRDNSequence(); len(subject) > 0 {
		subjectDER, err := asn1.Marshal(subject)
		if err != nil {
			return nil, fmt.Errorf("marshal CRMF subject: %w", err)
		}
		subjectField, err := marshalContext(5, true, subjectDER)
		if err != nil {
			return nil, err
		}
		templateFields = append(templateFields, subjectField)
	}
	if options.PublicKey != nil && len(options.publicKeyDER) > 0 {
		return nil, fmt.Errorf("CRMF public key and pre-encoded public key are mutually exclusive")
	}
	spkiDER := options.publicKeyDER
	if options.PublicKey != nil {
		spkiDER, err = x509.MarshalPKIXPublicKey(options.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal CRMF public key: %w", err)
		}
	}
	if len(spkiDER) > 0 {
		var spki asn1.RawValue
		if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
			return nil, fmt.Errorf("parse CRMF SubjectPublicKeyInfo: %w", err)
		}
		publicKeyField, err := marshalContext(6, true, spki.Bytes)
		if err != nil {
			return nil, err
		}
		templateFields = append(templateFields, publicKeyField)
	}
	if len(options.Extensions) > 0 {
		var extensionDER []byte
		for _, extension := range options.Extensions {
			der, err := asn1.Marshal(extension)
			if err != nil {
				return nil, fmt.Errorf("marshal CRMF extension: %w", err)
			}
			extensionDER = append(extensionDER, der...)
		}
		extensionsField, err := marshalContext(9, true, extensionDER)
		if err != nil {
			return nil, err
		}
		templateFields = append(templateFields, extensionsField)
	}
	templateDER, err := marshalSequence(templateFields...)
	if err != nil {
		return nil, err
	}
	requestParts := [][]byte{requestID, templateDER}
	controls, err := marshalControls(options)
	if err != nil {
		return nil, err
	}
	if len(controls) > 0 {
		requestParts = append(requestParts, controls)
	}
	return marshalSequence(requestParts...)
}

func marshalEmptySubjectPublicKeyInfo(algorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	var algorithmID pkix.AlgorithmIdentifier
	switch algorithm {
	case x509.RSA:
		algorithmID = pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}
	case x509.ECDSA:
		algorithmID = pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey}
	default:
		return nil, fmt.Errorf("unsupported KGA key algorithm %v", algorithm)
	}
	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{Algorithm: algorithmID, PublicKey: asn1.BitString{}})
}

func marshalControls(options EnrollmentRequestOptions) ([]byte, error) {
	var attrs [][]byte
	for _, value := range []struct {
		oid  asn1.ObjectIdentifier
		text string
	}{
		{oidRegCtrlRegToken, options.RegToken},
		{oidRegCtrlAuthenticator, options.Authenticator},
	} {
		if value.text == "" {
			continue
		}
		der, err := asn1.MarshalWithParams(value.text, "utf8")
		if err != nil {
			return nil, err
		}
		attr, err := marshalAttribute(value.oid, der)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	if options.OldCertID != nil {
		issuer := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: options.OldCertID.IssuerNameDER}
		issuerDER, err := asn1.Marshal(issuer)
		if err != nil {
			return nil, err
		}
		serialDER, err := asn1.Marshal(options.OldCertID.SerialNumber)
		if err != nil {
			return nil, err
		}
		certID, err := marshalSequence(issuerDER, serialDER)
		if err != nil {
			return nil, err
		}
		attr, err := marshalAttribute(oidRegCtrlOldCertID, certID)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	if len(attrs) == 0 {
		return nil, nil
	}
	return marshalSequence(attrs...)
}

func marshalAttribute(oid asn1.ObjectIdentifier, valueDER []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	return marshalSequence(oidDER, valueDER)
}

func marshalPOPOSigningKey(certRequestDER []byte, signer crypto.Signer) ([]byte, error) {
	algorithm, hash, err := ProtectionAlgorithm(signer)
	if err != nil {
		return nil, err
	}
	signature, err := SignPayload(signer, hash, certRequestDER)
	if err != nil {
		return nil, err
	}
	algorithmDER, err := asn1.Marshal(algorithm)
	if err != nil {
		return nil, err
	}
	signatureDER, err := asn1.Marshal(asn1.BitString{Bytes: signature, BitLength: len(signature) * 8})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: append(algorithmDER, signatureDER...)})
}

// BuildP10CRRequest creates a p10cr body from a signed PKCS#10 request.
func BuildP10CRRequest(request *x509.CertificateRequest) (EncodedBody, error) {
	if request == nil || len(request.Raw) == 0 {
		return EncodedBody{}, fmt.Errorf("a parsed, signed PKCS#10 request is required")
	}
	if err := request.CheckSignature(); err != nil {
		return EncodedBody{}, fmt.Errorf("invalid PKCS#10 signature: %w", err)
	}
	return EncodedBody{Type: BodyP10CR, DER: append([]byte(nil), request.Raw...)}, nil
}

// RevocationRequestOptions describes one RevDetails entry.
type RevocationRequestOptions struct {
	SerialNumber *big.Int
	Issuer       *pkix.Name
	Reason       *int
}

// BuildRevocationRequest creates an rr body containing one RevDetails entry.
func BuildRevocationRequest(options RevocationRequestOptions) (EncodedBody, error) {
	if options.SerialNumber == nil || options.SerialNumber.Sign() < 0 {
		return EncodedBody{}, fmt.Errorf("a non-negative certificate serial number is required")
	}
	serialDER, err := asn1.Marshal(options.SerialNumber)
	if err != nil {
		return EncodedBody{}, err
	}
	serialField, err := marshalContext(1, true, serialDER)
	if err != nil {
		return EncodedBody{}, err
	}
	fields := [][]byte{serialField}
	if options.Issuer != nil {
		issuer, err := GeneralNameDirectoryName(*options.Issuer)
		if err != nil {
			return EncodedBody{}, err
		}
		issuerField, err := marshalContext(3, true, issuer.Bytes)
		if err != nil {
			return EncodedBody{}, err
		}
		fields = append(fields, issuerField)
	}
	template, err := marshalSequence(fields...)
	if err != nil {
		return EncodedBody{}, err
	}
	revDetailsParts := [][]byte{template}
	if options.Reason != nil {
		if !IsKnownCRLReason(*options.Reason) {
			return EncodedBody{}, fmt.Errorf("unknown CRL reason %d", *options.Reason)
		}
		reasonDER, err := asn1.Marshal(asn1.Enumerated(*options.Reason))
		if err != nil {
			return EncodedBody{}, err
		}
		extensionDER, err := asn1.Marshal(pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 21}, Value: reasonDER})
		if err != nil {
			return EncodedBody{}, err
		}
		extensions, err := marshalSequence(extensionDER)
		if err != nil {
			return EncodedBody{}, err
		}
		revDetailsParts = append(revDetailsParts, extensions)
	}
	revDetails, err := marshalSequence(revDetailsParts...)
	if err != nil {
		return EncodedBody{}, err
	}
	content, err := marshalSequence(revDetails)
	if err != nil {
		return EncodedBody{}, err
	}
	return EncodedBody{Type: BodyRR, DER: content}, nil
}

// CertConfirmation describes one CertStatus in certConf.
type CertConfirmation struct {
	Certificate *x509.Certificate
	CertReqID   int
	HashOID     asn1.ObjectIdentifier
	Status      *PKIStatusInfo
}

// BuildCertConf creates a certConf body.
func BuildCertConf(confirmations ...CertConfirmation) (EncodedBody, error) {
	if len(confirmations) == 0 {
		return EncodedBody{}, fmt.Errorf("at least one certificate confirmation is required")
	}
	var entries [][]byte
	for _, confirmation := range confirmations {
		if confirmation.Certificate == nil {
			return EncodedBody{}, fmt.Errorf("certificate confirmation requires a certificate")
		}
		hash, err := ComputeCertHash(confirmation.Certificate.Raw, confirmation.HashOID)
		if err != nil {
			return EncodedBody{}, err
		}
		hashDER, _ := asn1.Marshal(hash)
		requestIDDER, _ := asn1.Marshal(confirmation.CertReqID)
		parts := [][]byte{hashDER, requestIDDER}
		if confirmation.Status != nil {
			statusDER, err := asn1.Marshal(*confirmation.Status)
			if err != nil {
				return EncodedBody{}, err
			}
			parts = append(parts, statusDER)
		}
		if len(confirmation.HashOID) > 0 {
			algorithmDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: confirmation.HashOID})
			if err != nil {
				return EncodedBody{}, err
			}
			hashAlgorithm, err := marshalContext(0, true, algorithmDER)
			if err != nil {
				return EncodedBody{}, err
			}
			parts = append(parts, hashAlgorithm)
		}
		entry, err := marshalSequence(parts...)
		if err != nil {
			return EncodedBody{}, err
		}
		entries = append(entries, entry)
	}
	content, err := marshalSequence(entries...)
	if err != nil {
		return EncodedBody{}, err
	}
	return EncodedBody{Type: BodyCertConf, DER: content}, nil
}

// BuildPKIConf creates the NULL pkiConf body sent after successful explicit
// certificate confirmation.
func BuildPKIConf() (EncodedBody, error) {
	der, err := MarshalPKIConfBody()
	return EncodedBody{Type: BodyPKIConf, DER: der}, err
}

// BuildPollReq creates a pollReq body for one or more request identifiers.
func BuildPollReq(certReqIDs ...int) (EncodedBody, error) {
	if len(certReqIDs) == 0 {
		return EncodedBody{}, fmt.Errorf("at least one certReqId is required")
	}
	var entries [][]byte
	for _, id := range certReqIDs {
		idDER, _ := asn1.Marshal(id)
		entry, err := marshalSequence(idDER)
		if err != nil {
			return EncodedBody{}, err
		}
		entries = append(entries, entry)
	}
	content, err := marshalSequence(entries...)
	return EncodedBody{Type: BodyPollReq, DER: content}, err
}

// BuildGenMsg creates a general-message body.
func BuildGenMsg(values ...InfoTypeAndValue) (EncodedBody, error) {
	if len(values) == 0 {
		return EncodedBody{}, fmt.Errorf("at least one InfoTypeAndValue is required")
	}
	der, err := asn1.Marshal(values)
	return EncodedBody{Type: BodyGenMsg, DER: der}, err
}

// BuildNested creates a nested body from complete DER-encoded PKIMessages.
func BuildNested(messages ...[]byte) (EncodedBody, error) {
	if len(messages) == 0 {
		return EncodedBody{}, fmt.Errorf("at least one nested PKIMessage is required")
	}
	values := make([]asn1.RawValue, 0, len(messages))
	for _, message := range messages {
		if _, err := ParseRawMessage(message); err != nil {
			return EncodedBody{}, fmt.Errorf("invalid nested PKIMessage: %w", err)
		}
		values = append(values, asn1.RawValue{FullBytes: message})
	}
	der, err := asn1.Marshal(values)
	return EncodedBody{Type: BodyNested, DER: der}, err
}

func marshalSequence(parts ...[]byte) ([]byte, error) {
	var content []byte
	for _, part := range parts {
		content = append(content, part...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

func marshalContext(tag int, compound bool, content []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: compound, Bytes: content})
}
