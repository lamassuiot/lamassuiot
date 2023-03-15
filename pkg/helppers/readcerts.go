package helppers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func ReadCertificateFromFile(filePath string) (*x509.Certificate, error) {
	if filePath == "" {
		return nil, fmt.Errorf("cannot open empty filepath")
	}

	certFileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	certDERBlock, _ := pem.Decode(certFileBytes)

	return x509.ParseCertificate(certDERBlock.Bytes)
}
