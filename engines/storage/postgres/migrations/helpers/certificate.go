package helpers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func DecodeCertificate(base64Cert string) (*x509.Certificate, error) {
	decodedPEM, err := base64.StdEncoding.DecodeString(base64Cert)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(decodedPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(certBlock.Bytes)
}
