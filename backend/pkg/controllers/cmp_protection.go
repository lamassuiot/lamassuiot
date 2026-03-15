package controllers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

type responsePKIMessage struct {
	Header     responsePKIHeader
	Body       asn1.RawValue
	Protection asn1.BitString     `asn1:"explicit,optional,tag:0,omitempty"`
	ExtraCerts []responseCMPCerts `asn1:"explicit,optional,tag:1,omitempty"`
}

type responseCMPCerts struct {
	Raw asn1.RawContent
}

type rawResponsePKIMessage struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
	ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

func marshalProtectedResponse(
	reqHeader requestPKIHeader,
	bodyTag int,
	bodyDER []byte,
	cert *x509.Certificate,
	signer crypto.Signer,
) ([]byte, error) {
	protectionAlg, hash, err := cmpProtectionAlgorithm(signer)
	if err != nil {
		return nil, err
	}

	respHeader := buildResponseHeader(reqHeader)
	respHeader.MessageTime = time.Now().UTC().Round(time.Second)
	respHeader.ProtectionAlg = protectionAlg
	respSender, err := generalNameDirectoryName(cert.Subject)
	if err != nil {
		return nil, fmt.Errorf("marshal cmp sender general name: %w", err)
	}
	respHeader.Sender = respSender

	msg := responsePKIMessage{
		Header: respHeader,
		Body: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        bodyTag,
			IsCompound: true,
			Bytes:      bodyDER,
		},
		ExtraCerts: []responseCMPCerts{{Raw: cert.Raw}},
	}

	encoded, err := asn1.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal protected response skeleton: %w", err)
	}

	var rawMsg rawResponsePKIMessage
	if _, err := asn1.Unmarshal(encoded, &rawMsg); err != nil {
		return nil, fmt.Errorf("parse protected response skeleton: %w", err)
	}

	signedData, err := marshalProtectedPayload(rawMsg.Header.FullBytes, rawMsg.Body.FullBytes)
	if err != nil {
		return nil, err
	}

	signature, err := signCMPPayload(signer, hash, signedData)
	if err != nil {
		return nil, err
	}

	msg.Protection = asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}

	finalDER, err := asn1.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal protected response: %w", err)
	}
	return finalDER, nil
}

func generalNameDirectoryName(name pkix.Name) (asn1.RawValue, error) {
	type generalName struct {
		RDNSequence pkix.RDNSequence
	}

	fullBytes, err := asn1.MarshalWithParams(generalName{
		RDNSequence: name.ToRDNSequence(),
	}, "tag:4")
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: fullBytes}, nil
}

func marshalUnprotectedResponse(reqHeader requestPKIHeader, bodyTag int, bodyDER []byte) ([]byte, error) {
	respHeader := buildResponseHeader(reqHeader)
	return asn1.Marshal(responsePKIMessage{
		Header: respHeader,
		Body: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        bodyTag,
			IsCompound: true,
			Bytes:      bodyDER,
		},
	})
}

func marshalProtectedPayload(headerDER, bodyDER []byte) ([]byte, error) {
	payload := make([]byte, 0, len(headerDER)+len(bodyDER))
	payload = append(payload, headerDER...)
	payload = append(payload, bodyDER...)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      payload,
	})
}

func signCMPPayload(signer crypto.Signer, hash crypto.Hash, payload []byte) ([]byte, error) {
	if hash == 0 {
		sig, err := signer.Sign(rand.Reader, payload, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("sign cmp payload: %w", err)
		}
		return sig, nil
	}

	hasher := hash.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	sig, err := signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("sign cmp payload: %w", err)
	}
	return sig, nil
}

func cmpProtectionAlgorithm(signer crypto.Signer) (pkix.AlgorithmIdentifier, crypto.Hash, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
			Parameters: asn1.NullRawValue,
		}, crypto.SHA256, nil
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
			Parameters: asn1.NullRawValue,
		}, crypto.SHA256, nil
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		}, 0, nil
	default:
		return pkix.AlgorithmIdentifier{}, 0, fmt.Errorf("unsupported cmp protection key type: %T", signer.Public())
	}
}
