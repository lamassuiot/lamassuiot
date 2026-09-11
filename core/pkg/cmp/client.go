package cmp

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

// HeaderOptions configures a client-generated PKIHeader. Missing transaction
// and sender nonces are generated with crypto/rand.
type HeaderOptions struct {
	PVNO          int
	Sender        GeneralName
	Recipient     GeneralName
	MessageTime   time.Time
	TransactionID []byte
	SenderNonce   []byte
	RecipNonce    []byte
	GeneralInfo   []InfoTypeAndValue
}

// NewHeader creates a complete client PKIHeader with secure defaults.
func NewHeader(options HeaderOptions) (Header, error) {
	if len(options.Sender.FullBytes) == 0 || len(options.Recipient.FullBytes) == 0 {
		return Header{}, fmt.Errorf("CMP sender and recipient GeneralName are required")
	}
	if options.PVNO == 0 {
		options.PVNO = PVNOCMP2000
	}
	if options.PVNO != PVNOCMP2000 && options.PVNO != PVNOCMP2021 {
		return Header{}, fmt.Errorf("unsupported CMP protocol version %d", options.PVNO)
	}
	if options.MessageTime.IsZero() {
		options.MessageTime = time.Now().UTC().Round(time.Second)
	}
	var err error
	if len(options.TransactionID) == 0 {
		options.TransactionID, err = NewNonce()
		if err != nil {
			return Header{}, err
		}
	}
	if len(options.SenderNonce) == 0 {
		options.SenderNonce, err = NewNonce()
		if err != nil {
			return Header{}, err
		}
	}
	return Header{
		PVNO:          options.PVNO,
		Sender:        options.Sender,
		Recipient:     options.Recipient,
		MessageTime:   options.MessageTime,
		TransactionID: options.TransactionID,
		SenderNonce:   options.SenderNonce,
		RecipNonce:    options.RecipNonce,
		GeneralInfo:   options.GeneralInfo,
	}, nil
}

// MarshalUnprotected encodes body as an unprotected PKIMessage.
func MarshalUnprotected(header Header, body EncodedBody) ([]byte, error) {
	return MarshalUnprotectedMessage(header, int(body.Type), body.DER)
}

// MarshalProtected encodes and signs body as a protected PKIMessage.
func MarshalProtected(header Header, body EncodedBody, certChain []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	return MarshalProtectedMessage(header, int(body.Type), body.DER, certChain, signer)
}

// ParsedMessage is the typed representation returned by ParseMessage. Raw
// retains the original component DER needed for signature verification.
type ParsedMessage struct {
	Header     Header
	Body       EncodedBody
	Protection asn1.BitString
	ExtraCerts []*x509.Certificate
	Raw        RawMessage
}

// ParseMessage parses the common PKIMessage fields and its body tag. Use
// body-specific decoders for Body.DER.
func ParseMessage(der []byte) (ParsedMessage, error) {
	raw, err := ParseRawMessage(der)
	if err != nil {
		return ParsedMessage{}, err
	}
	var header Header
	if rest, err := asn1.Unmarshal(raw.Header.FullBytes, &header); err != nil || len(rest) != 0 {
		if err == nil {
			err = fmt.Errorf("%d trailing header bytes", len(rest))
		}
		return ParsedMessage{}, fmt.Errorf("parse CMP header: %w", err)
	}
	parsed := ParsedMessage{
		Header: header,
		Body:   EncodedBody{Type: BodyType(raw.Body.Tag), DER: append([]byte(nil), raw.Body.Bytes...)},
		Raw:    raw,
	}
	if len(raw.Protection.Bytes) > 0 {
		if _, err := asn1.Unmarshal(raw.Protection.Bytes, &parsed.Protection); err != nil {
			return ParsedMessage{}, fmt.Errorf("parse CMP protection: %w", err)
		}
	}
	for _, certRaw := range raw.ExtraCerts {
		cert, err := ParseLeafExtraCert(certRaw)
		if err != nil {
			return ParsedMessage{}, err
		}
		parsed.ExtraCerts = append(parsed.ExtraCerts, cert)
	}
	return parsed, nil
}

// VerifySignature verifies only the cryptographic CMP message protection. It
// does not establish trust in the returned signer certificate.
func (message ParsedMessage) VerifySignature(required bool) (*x509.Certificate, error) {
	return VerifyMessageProtection(message.Raw, message.Header.ProtectionAlg, required)
}

// VerifyTrust validates signer against roots after cryptographic protection
// verification. Intermediates may be nil.
func (message ParsedMessage) VerifyTrust(roots, intermediates *x509.CertPool, required bool) (*x509.Certificate, error) {
	signer, err := message.VerifySignature(required)
	if err != nil || signer == nil {
		return signer, err
	}
	if roots == nil {
		return nil, fmt.Errorf("CMP signer trust roots are required")
	}
	if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: message.Header.MessageTime}); err != nil {
		return nil, fmt.Errorf("verify CMP signer trust: %w", err)
	}
	return signer, nil
}
