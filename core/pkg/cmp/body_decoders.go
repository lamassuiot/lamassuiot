package cmp

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// DecodeEnrollmentRequest decodes the first CRMF CertReqMsg in ir, cr, or kur.
func DecodeEnrollmentRequest(body EncodedBody) (*CertRequest, error) {
	if body.Type != BodyIR && body.Type != BodyCR && body.Type != BodyKUR {
		return nil, fmt.Errorf("body type %d is not a CRMF enrollment request", body.Type)
	}
	return DecodeFirstCertReq(body.DER)
}

// DecodeP10CRRequest parses the PKCS#10 request carried by p10cr.
func DecodeP10CRRequest(body EncodedBody) (*x509.CertificateRequest, error) {
	if body.Type != BodyP10CR {
		return nil, fmt.Errorf("body type %d is not p10cr", body.Type)
	}
	request, err := x509.ParseCertificateRequest(body.DER)
	if err != nil {
		return nil, fmt.Errorf("parse p10cr certificate request: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify p10cr certificate request: %w", err)
	}
	return request, nil
}

// DecodeGenMsg decodes a genm body.
func DecodeGenMsg(body EncodedBody) ([]InfoTypeAndValue, error) {
	if body.Type != BodyGenMsg && body.Type != BodyGenRep {
		return nil, fmt.Errorf("body type %d is not genm/genp", body.Type)
	}
	var values []InfoTypeAndValue
	rest, err := asn1.Unmarshal(body.DER, &values)
	if err != nil {
		return nil, fmt.Errorf("decode general message: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("decode general message: %d trailing bytes", len(rest))
	}
	return values, nil
}

// DecodeNested decodes the complete PKIMessages carried by a nested body.
func DecodeNested(body EncodedBody) ([]RawMessage, error) {
	if body.Type != BodyNested {
		return nil, fmt.Errorf("body type %d is not nested", body.Type)
	}
	var values []asn1.RawValue
	rest, err := asn1.Unmarshal(body.DER, &values)
	if err != nil {
		return nil, fmt.Errorf("decode nested messages: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("decode nested messages: %d trailing bytes", len(rest))
	}
	messages := make([]RawMessage, 0, len(values))
	for _, value := range values {
		message, err := ParseRawMessage(value.FullBytes)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}
