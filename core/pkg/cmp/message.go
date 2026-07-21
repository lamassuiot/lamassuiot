package cmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/cms"
)

// InfoTypeAndValue is the CMP InfoTypeAndValue structure used by PKIHeader
// generalInfo and general-message bodies.
type InfoTypeAndValue struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}

// Header is the wire representation of a CMP PKIHeader.
type Header struct {
	PVNO          int `asn1:"default:2"`
	Sender        GeneralName
	Recipient     GeneralName
	MessageTime   time.Time                `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	SenderKID     []byte                   `asn1:"optional,explicit,tag:2,omitempty"`
	TransactionID []byte                   `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5,omitempty"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6,omitempty"`
	GeneralInfo   []InfoTypeAndValue       `asn1:"optional,explicit,tag:8,omitempty"`
}

// CMPCertificate embeds an already DER-encoded X.509 certificate in
// PKIMessage.extraCerts.
type CMPCertificate struct {
	Raw asn1.RawContent
}

// Message is the wire representation of a complete CMP PKIMessage.
type Message struct {
	Header     Header
	Body       asn1.RawValue
	Protection asn1.BitString   `asn1:"explicit,optional,tag:0,omitempty"`
	ExtraCerts []CMPCertificate `asn1:"explicit,optional,tag:1,omitempty"`
}

// RawMessage preserves the exact DER for each PKIMessage component. It is
// useful for signature verification because CMP protection covers the encoded
// header and body, not a re-encoding of decoded values.
type RawMessage struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

// Body returns a PKIBody CHOICE containing bodyDER under the requested CMP
// context-specific body tag.
func Body(tag int, bodyDER []byte) asn1.RawValue {
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      bodyDER,
	}
}

// MarshalMessage encodes a complete PKIMessage. The body and any protection
// or extra certificates are taken directly from msg.
func MarshalMessage(msg Message) ([]byte, error) {
	der, err := asn1.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal CMP PKIMessage: %w", err)
	}
	return der, nil
}

// ParseRawMessage decodes a PKIMessage while retaining the exact DER of its
// header and body for protection verification.
func ParseRawMessage(der []byte) (RawMessage, error) {
	var msg RawMessage
	rest, err := asn1.Unmarshal(der, &msg)
	if err != nil {
		return RawMessage{}, protocolError("parse CMP PKIMessage", FailureBadDataFormat, err)
	}
	if len(rest) != 0 {
		return RawMessage{}, protocolError("parse CMP PKIMessage", FailureBadDataFormat, fmt.Errorf("%d trailing bytes", len(rest)))
	}
	return msg, nil
}

// MarshalUnprotectedMessage creates an unprotected PKIMessage from a header
// and an already DER-encoded PKIBody payload.
func MarshalUnprotectedMessage(header Header, bodyTag int, bodyDER []byte) ([]byte, error) {
	return MarshalMessage(Message{Header: header, Body: Body(bodyTag, bodyDER)})
}

// MarshalProtectedMessage signs a PKIMessage and places certChain in
// extraCerts, using certChain[0] as the protection certificate.
func MarshalProtectedMessage(header Header, bodyTag int, bodyDER []byte, certChain []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("marshal protected CMP message: certificate chain must not be empty")
	}
	return MarshalProtectedMessageWithSigner(header, bodyTag, bodyDER, certChain, certChain[0], signer)
}

// MarshalProtectedMessageWithSigner is MarshalProtectedMessage with the
// protection signer certificate decoupled from extraCerts[0].
func MarshalProtectedMessageWithSigner(header Header, bodyTag int, bodyDER []byte, extraCertChain []*x509.Certificate, signerCert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if len(extraCertChain) == 0 {
		return nil, fmt.Errorf("marshal protected CMP message: certificate chain must not be empty")
	}
	if signerCert == nil || signer == nil {
		return nil, fmt.Errorf("marshal protected CMP message: signer certificate and signer are required")
	}

	protectionAlg, hash, err := ProtectionAlgorithm(signer)
	if err != nil {
		return nil, err
	}
	header.ProtectionAlg = protectionAlg
	if header.MessageTime.IsZero() {
		header.MessageTime = time.Now().UTC().Round(time.Second)
	}
	if len(signerCert.SubjectKeyId) > 0 {
		header.SenderKID = signerCert.SubjectKeyId
	}
	if len(header.Sender.FullBytes) == 0 {
		header.Sender, err = GeneralNameDirectoryName(signerCert.Subject)
		if err != nil {
			return nil, fmt.Errorf("marshal CMP sender GeneralName: %w", err)
		}
	}

	extraCerts := make([]CMPCertificate, len(extraCertChain))
	for i, cert := range extraCertChain {
		extraCerts[i] = CMPCertificate{Raw: cert.Raw}
	}
	msg := Message{Header: header, Body: Body(bodyTag, bodyDER), ExtraCerts: extraCerts}
	skeleton, err := MarshalMessage(msg)
	if err != nil {
		return nil, err
	}
	raw, err := ParseRawMessage(skeleton)
	if err != nil {
		return nil, err
	}
	payload, err := MarshalProtectedPayload(raw.Header.FullBytes, raw.Body.FullBytes)
	if err != nil {
		return nil, err
	}
	signature, err := SignPayload(signer, hash, payload)
	if err != nil {
		return nil, err
	}
	msg.Protection = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	return MarshalMessage(msg)
}

// MarshalProtectedPayload encodes the CMP ProtectedPart from the exact DER of
// a PKIHeader and PKIBody.
func MarshalProtectedPayload(headerDER, bodyDER []byte) ([]byte, error) {
	payload := make([]byte, 0, len(headerDER)+len(bodyDER))
	payload = append(payload, headerDER...)
	payload = append(payload, bodyDER...)
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: payload})
}

// SignPayload signs a DER-encoded CMP ProtectedPart with signer.
func SignPayload(signer crypto.Signer, hash crypto.Hash, payload []byte) ([]byte, error) {
	if hash == 0 {
		sig, err := signer.Sign(rand.Reader, payload, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("sign CMP payload: %w", err)
		}
		return sig, nil
	}
	hasher := hash.New()
	_, _ = hasher.Write(payload)
	sig, err := signer.Sign(rand.Reader, hasher.Sum(nil), hash)
	if err != nil {
		return nil, fmt.Errorf("sign CMP payload: %w", err)
	}
	return sig, nil
}

// ProtectionAlgorithm selects a CMP signature AlgorithmIdentifier and hash
// appropriate for signer.
func ProtectionAlgorithm(signer crypto.Signer) (pkix.AlgorithmIdentifier, crypto.Hash, error) {
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		switch bits := pub.N.BitLen(); {
		case bits > 7680:
			return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, Parameters: asn1.NullRawValue}, crypto.SHA512, nil
		case bits > 3072:
			return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, Parameters: asn1.NullRawValue}, crypto.SHA384, nil
		default:
			// SHA-256 profile: shared with the CMS layer, sourced from cms.
			return pkix.AlgorithmIdentifier{Algorithm: cms.OIDSHA256WithRSA(), Parameters: asn1.NullRawValue}, crypto.SHA256, nil
		}
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 521:
			return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}}, crypto.SHA512, nil
		case 384:
			return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}}, crypto.SHA384, nil
		default:
			// SHA-256 profile: shared with the CMS layer, sourced from cms.
			return pkix.AlgorithmIdentifier{Algorithm: cms.OIDECDSAWithSHA256()}, crypto.SHA256, nil
		}
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}, 0, nil
	default:
		return pkix.AlgorithmIdentifier{}, 0, fmt.Errorf("unsupported CMP protection key type: %T", signer.Public())
	}
}

// GeneralNameDirectoryName encodes an X.509 name as the directoryName
// alternative of GeneralName.
func GeneralNameDirectoryName(name pkix.Name) (asn1.RawValue, error) {
	type generalName struct{ RDNSequence pkix.RDNSequence }
	der, err := asn1.MarshalWithParams(generalName{RDNSequence: name.ToRDNSequence()}, "tag:4")
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: der}, nil
}

// NewNonce returns a fresh 16-byte CMP sender nonce.
func NewNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("CMP nonce CSPRNG read: %w", err)
	}
	return nonce, nil
}

// ProtectionAlgorithmError reports a protection algorithm or integrity-type
// rejection together with its CMP PKIFailureInfo bit.
type ProtectionAlgorithmError struct {
	Message        string
	FailureInfoBit int
}

func (e *ProtectionAlgorithmError) Error() string { return e.Message }

// ProtectionAlgorithmFailureInfo extracts a CMP PKIFailureInfo bit from err.
func ProtectionAlgorithmFailureInfo(err error) (int, bool) {
	var algErr *ProtectionAlgorithmError
	if errors.As(err, &algErr) {
		return algErr.FailureInfoBit, true
	}
	return 0, false
}

// ParseLeafExtraCert parses the first certificate representation used by
// RawMessage.ExtraCerts.
func ParseLeafExtraCert(raw asn1.RawValue) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(raw.FullBytes)
	if err != nil {
		var first asn1.RawValue
		if _, innerErr := asn1.Unmarshal(raw.Bytes, &first); innerErr == nil {
			if parsed, parseErr := x509.ParseCertificate(first.FullBytes); parseErr == nil {
				return parsed, nil
			}
		}
	}
	if cert != nil {
		return cert, nil
	}
	cert, fallbackErr := x509.ParseCertificate(raw.Bytes)
	if fallbackErr != nil {
		return nil, fmt.Errorf("parse certificate from extraCerts: full DER error=%v, content error=%v", err, fallbackErr)
	}
	return cert, nil
}

// VerifyMessageProtection verifies signature-based protection using the first
// certificate in extraCerts. An unprotected message is accepted only when
// required is false.
func VerifyMessageProtection(msg RawMessage, protectionAlg pkix.AlgorithmIdentifier, required bool) (*x509.Certificate, error) {
	if len(msg.Protection.Bytes) == 0 {
		if required {
			return nil, fmt.Errorf("CMP message protection is required")
		}
		return nil, nil
	}
	if protectionAlg.Algorithm.Equal(oidPasswordBasedMAC) || protectionAlg.Algorithm.Equal(oidDHBasedMAC) {
		return nil, &ProtectionAlgorithmError{Message: fmt.Sprintf("MAC-based CMP protection %s is not supported", protectionAlg.Algorithm), FailureInfoBit: PKIFailureInfoWrongIntegrity}
	}
	if len(msg.ExtraCerts) == 0 {
		return nil, fmt.Errorf("CMP protection is present but extraCerts is empty")
	}
	cert, err := ParseLeafExtraCert(msg.ExtraCerts[0])
	if err != nil {
		return nil, err
	}
	payload, err := MarshalProtectedPayload(msg.Header.FullBytes, msg.Body.FullBytes)
	if err != nil {
		return nil, err
	}
	var bitString asn1.BitString
	if _, err := asn1.Unmarshal(msg.Protection.Bytes, &bitString); err != nil {
		return nil, fmt.Errorf("parse CMP protection BIT STRING: %w", err)
	}
	hash, err := HashFromSignatureAlgID(protectionAlg)
	if err != nil {
		return nil, &ProtectionAlgorithmError{Message: fmt.Sprintf("protection algorithm: %v", err), FailureInfoBit: PKIFailureInfoBadAlg}
	}
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if hash == 0 {
			return nil, fmt.Errorf("ECDSA CMP protection requires a hash")
		}
		h := hash.New()
		_, _ = h.Write(payload)
		if !ecdsa.VerifyASN1(pub, h.Sum(nil), bitString.Bytes) {
			return nil, fmt.Errorf("invalid ECDSA CMP protection signature")
		}
	case *rsa.PublicKey:
		if hash == 0 {
			return nil, fmt.Errorf("RSA CMP protection requires a hash")
		}
		h := hash.New()
		_, _ = h.Write(payload)
		digest := h.Sum(nil)
		if protectionAlg.Algorithm.String() == "1.2.840.113549.1.1.10" {
			err = rsa.VerifyPSS(pub, hash, digest, bitString.Bytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash})
		} else {
			err = rsa.VerifyPKCS1v15(pub, hash, digest, bitString.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid RSA CMP protection signature: %w", err)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, payload, bitString.Bytes) {
			return nil, fmt.Errorf("invalid Ed25519 CMP protection signature")
		}
	default:
		return nil, fmt.Errorf("unsupported CMP protection public key type %T", pub)
	}
	return cert, nil
}
