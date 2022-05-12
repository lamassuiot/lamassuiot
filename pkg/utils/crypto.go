package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParseKeycloakPublicKey(data []byte) (*rsa.PublicKey, error) {
	pubPem, _ := pem.Decode(data)
	parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, errors.New("Unable to parse public key")
	}
	pubKey := parsedKey.(*rsa.PublicKey)
	return pubKey, nil
}

func GenerateCSR(csr *x509.CertificateRequest, key interface{}) (*x509.CertificateRequest, error) {

	subj := pkix.Name{
		Country:            []string{csr.Subject.Country[0]},
		Province:           []string{csr.Subject.Province[0]},
		Organization:       []string{csr.Subject.Organization[0]},
		OrganizationalUnit: []string{csr.Subject.OrganizationalUnit[0]},
		Locality:           []string{csr.Subject.Locality[0]},
		CommonName:         csr.Subject.CommonName,
	}
	rawSubject := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubject)
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		//EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrNew, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}

const (
	CertPEMBlockType = "CERTIFICATE"
	KeyPEMBlockType  = "RSA PRIVATE KEY"
)

func CheckPEMBlock(pemBlock *pem.Block, blockType string) error {
	if pemBlock == nil {
		return errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != blockType || len(pemBlock.Headers) != 0 {
		return errors.New("unmatched type of headers")
	}
	return nil
}
