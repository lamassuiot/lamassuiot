package helpers

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// CreateDetachedPKCS7Signature creates a PKCS#7/CMS detached signature
// The message is not included in the output (detached signature)
// The certificate chain can optionally be included
func CreateDetachedPKCS7Signature(message []byte, signer crypto.Signer, signerCert *x509.Certificate) ([]byte, error) {
	if signerCert == nil {
		return nil, errors.New("signer certificate is required")
	}

	// Create SignedData structure
	signedData, err := pkcs7.NewSignedData(message)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	// Add the signer with the certificate
	if err := signedData.AddSigner(signerCert, signer, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("failed to add signer: %w", err)
	}

	// Create detached signature (remove the content)
	signedData.Detach()

	// Finish and encode the PKCS#7 structure
	pkcs7DER, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finish signed data: %w", err)
	}

	return pkcs7DER, nil
}

// CreateDetachedPKCS7SignatureWithChain creates a PKCS#7/CMS detached signature
// with the full certificate chain included
func CreateDetachedPKCS7SignatureWithChain(message []byte, signer crypto.Signer, signerCert *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	if signerCert == nil {
		return nil, errors.New("signer certificate is required")
	}

	// Create SignedData structure
	signedData, err := pkcs7.NewSignedData(message)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	// Add the signer with the certificate
	if err := signedData.AddSigner(signerCert, signer, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("failed to add signer: %w", err)
	}

	// Add chain certificates if provided
	for _, cert := range chain {
		if cert != nil {
			signedData.AddCertificate(cert)
		}
	}

	// Create detached signature (remove the content)
	signedData.Detach()

	// Finish and encode the PKCS#7 structure
	pkcs7DER, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finish signed data: %w", err)
	}

	return pkcs7DER, nil
}

// ParseCertificatePEM parses a PEM or base64-encoded certificate
func ParseCertificatePEM(certData string) (*x509.Certificate, error) {
	// Try base64 decode first (in case it's base64-encoded PEM or DER)
	decoded, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		// Not base64, try as raw PEM
		decoded = []byte(certData)
	}

	// Try to parse as PEM
	block, _ := pem.Decode(decoded)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	// Try to parse as raw DER
	return x509.ParseCertificate(decoded)
}
