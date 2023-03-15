package models

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// --------------------------------------------
type X509Certificate x509.Certificate

func (c *X509Certificate) MarshalJSON() ([]byte, error) {
	data := []byte{}

	if c != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		data = make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(data, pemCert)
		return json.Marshal(string(data))
	}

	return json.Marshal(data)
}

func (c *X509Certificate) UnmarshalJSON(data []byte) error {
	var decodedCert []byte
	err := json.Unmarshal(data, &decodedCert)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(decodedCert)
	if certBlock != nil {
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}

		*c = X509Certificate(*certificate)
		return nil
	}

	return fmt.Errorf("missing cert block")
}

// --------------------------------------------
type X509CertificateRequest x509.CertificateRequest

func (c *X509CertificateRequest) MarshalJSON() ([]byte, error) {
	data := []byte{}

	if c != nil {
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: c.Raw})
		data = make([]byte, base64.StdEncoding.EncodedLen(len(pemCert)))
		base64.StdEncoding.Encode(data, pemCert)
		return json.Marshal(string(data))
	}

	return json.Marshal(data)
}

func (c *X509CertificateRequest) UnmarshalJSON(data []byte) error {
	var decodedCert []byte
	err := json.Unmarshal(data, &decodedCert)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(decodedCert)
	if certBlock != nil {
		certificate, err := x509.ParseCertificateRequest(certBlock.Bytes)
		if err != nil {
			return err
		}

		*c = X509CertificateRequest(*certificate)
		return nil
	}

	return fmt.Errorf("missing cert block")
}

// --------------------------------------------
