package helpers

import (
	"testing"

	chelpers "github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
)

func TestValidateCertificate(t *testing.T) {
	// Load the CA certificate
	caCertFilePath := "testdata/cacertificate.pem"
	caCert, err := chelpers.ReadCertificateFromFile(caCertFilePath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate from file: %v", err)
	}

	// Load the certificate to be validated
	certFilePath := "testdata/samecaeccertificate.pem"
	cert, err := chelpers.ReadCertificateFromFile(certFilePath)
	if err != nil {
		t.Fatalf("Failed to read certificate from file: %v", err)
	}

	// Call the ValidateCertificate function
	err = ValidateCertificate(caCert, cert, false)

	// Check if an error occurred during validation
	if err != nil {
		t.Errorf("Certificate validation failed: %v", err)
	}

	// Load the certificate to be validated
	certFilePath = "testdata/noncacert.pem"
	cert, err = chelpers.ReadCertificateFromFile(certFilePath)
	if err != nil {
		t.Fatalf("Failed to read certificate from file: %v", err)
	}

	// Call the ValidateCertificate function
	err = ValidateCertificate(caCert, cert, false)

	// Check if an error occurred during validation
	if err == nil {
		t.Errorf("Certificate validation should have failed")
	}

}
