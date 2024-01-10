package helpers

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestReadCertificateFromFile(t *testing.T) {
	// Test case 1: Valid file path
	filePath := "testdata/cacertificate.pem"
	cert, err := ReadCertificateFromFile(filePath)
	if err != nil {
		t.Errorf("ReadCertificateFromFile failed for valid file path: %v", err)
	}

	// Verify that the returned certificate is not nil
	if cert == nil {
		t.Error("ReadCertificateFromFile returned nil certificate for valid file path")
	}

	// Test case 2: Empty file path
	filePath = ""
	_, err = ReadCertificateFromFile(filePath)
	if err == nil {
		t.Error("ReadCertificateFromFile should have returned an error for empty file path")
	}

	// Test case 3: Non-existent file path
	filePath = "testdata/nonexistent.pem"
	_, err = ReadCertificateFromFile(filePath)
	if err == nil {
		t.Error("ReadCertificateFromFile should have returned an error for non-existent file path")
	}

	// Test case 4: Invalid certificate file
	filePath = "testdata/invalid.pem"
	_, err = ReadCertificateFromFile(filePath)
	if err == nil {
		t.Error("ReadCertificateFromFile should have returned an error for invalid certificate file")
	}
}

func TestReadPrivateKeyFromFile(t *testing.T) {
	// Test case 1: Valid file path
	filePath := "testdata/privatekey.pem"
	key, err := ReadPrivateKeyFromFile(filePath)
	if err != nil {
		t.Errorf("ReadPrivateKeyFromFile failed for valid file path: %v", err)
	}

	// Verify that the returned key is not nil
	if key == nil {
		t.Error("ReadPrivateKeyFromFile returned nil key for valid file path")
	}

	filePath = "testdata/ecprivatekey.pem"
	key, err = ReadPrivateKeyFromFile(filePath)
	if err != nil {
		t.Errorf("ReadPrivateKeyFromFile failed for valid file path: %v", err)
	}

	// Verify that the returned key is not nil
	if key == nil {
		t.Error("ReadPrivateKeyFromFile returned nil key for valid file path")
	}

	filePath = "testdata/pkcs1pk.pem"
	key, err = ReadPrivateKeyFromFile(filePath)
	if err != nil {
		t.Errorf("ReadPrivateKeyFromFile failed for valid file path: %v", err)
	}

	// Verify that the returned key is not nil
	if key == nil {
		t.Error("ReadPrivateKeyFromFile returned nil key for valid file path")
	}

	// Test case 2: Empty file path
	filePath = ""
	_, err = ReadPrivateKeyFromFile(filePath)
	if err == nil {
		t.Error("ReadPrivateKeyFromFile should have returned an error for empty file path")
	}

	// Test case 3: Non-existent file path
	filePath = "testdata/nonexistent.pem"
	_, err = ReadPrivateKeyFromFile(filePath)
	if err == nil {
		t.Error("ReadPrivateKeyFromFile should have returned an error for non-existent file path")
	}

	// Test case 4: Invalid private key file
	filePath = "testdata/invalid.pem"
	_, err = ReadPrivateKeyFromFile(filePath)
	if err == nil {
		t.Error("ReadPrivateKeyFromFile should have returned an error for invalid private key file")
	}
}

func TestCertificateToPEM(t *testing.T) {
	// Test case 1: Valid certificate
	certFilePath := "testdata/cacertificate.pem"
	cert, err := ReadCertificateFromFile(certFilePath)
	if err != nil {
		t.Errorf("Failed to read certificate from file: %v", err)
	}

	pemCert := CertificateToPEM(cert)

	// Verify that the returned PEM certificate is not empty
	if pemCert == "" {
		t.Error("CertificateToPEM returned an empty PEM certificate")
	}

	// Check that pemCert starts with "-----BEGIN CERTIFICATE-----"
	if !strings.HasPrefix(pemCert, "-----BEGIN CERTIFICATE-----") {
		t.Error("CertificateToPEM returned a PEM certificate that does not start with '-----BEGIN CERTIFICATE-----'")
	}

	// Check that pemCert ends with "-----END CERTIFICATE-----"
	if !strings.HasSuffix(pemCert, "-----END CERTIFICATE-----\n") {
		t.Error("CertificateToPEM returned a PEM certificate that does not end with '-----END CERTIFICATE-----\n'")
	}

}

func TestPrivateKeyToPEM(t *testing.T) {
	// Test case 1: Valid private key
	keyFilePath := "testdata/privatekey.pem"
	key, err := ReadPrivateKeyFromFile(keyFilePath)
	if err != nil {
		t.Errorf("Failed to read private key from file: %v", err)
	}

	pemKey, err := PrivateKeyToPEM(key)
	if err != nil {
		t.Errorf("PrivateKeyToPEM failed: %v", err)
	}

	// Verify that the returned PEM key is not empty
	if pemKey == "" {
		t.Error("PrivateKeyToPEM returned an empty PEM key")
	}

	// Check that pemKey starts with "-----BEGIN PRIVATE KEY-----"
	if !strings.HasPrefix(pemKey, "-----BEGIN PRIVATE KEY-----") {
		t.Error("PrivateKeyToPEM returned a PEM key that does not start with '-----BEGIN PRIVATE KEY-----'")
	}

	// Check that pemKey ends with "-----END PRIVATE KEY-----"
	if !strings.HasSuffix(pemKey, "-----END PRIVATE KEY-----\n") {
		t.Error("PrivateKeyToPEM returned a PEM key that does not end with '-----END PRIVATE KEY-----\n'")
	}
}

func TestGenerateSelfSignedCertificate(t *testing.T) {
	// Generate a private key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Test case 1: Valid certificate generation
	cn := "example.com"
	cert, err := GenerateSelfSignedCertificate(privateKey, cn)
	if err != nil {
		t.Errorf("Failed to generate self-signed certificate: %v", err)
	}

	// Verify that the returned certificate is not nil
	if cert == nil {
		t.Error("GenerateSelfSignedCertificate returned nil certificate")
	} else {
		// Verify that the certificate's common name matches the input
		if cert.Subject.CommonName != cn {
			t.Errorf("Generated certificate has incorrect common name. Expected: %s, Got: %s", cn, cert.Subject.CommonName)
		}

		// Verify that the certificate's public key matches the input private key
		if !cert.PublicKey.(*rsa.PublicKey).Equal(privateKey.Public()) {
			t.Error("Generated certificate has incorrect public key")
		}
	}

	// Test case 2: Invalid private key
	invalidPrivateKey := &rsa.PrivateKey{}
	_, err = GenerateSelfSignedCertificate(invalidPrivateKey, cn)
	if err == nil {
		t.Error("GenerateSelfSignedCertificate should have returned an error for invalid private key")
	}
}

func TestGenerateSelfSignedCertificateIntegration(t *testing.T) {
	// Generate a private key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Generate a self-signed certificate
	cn := "example.com"
	cert, err := GenerateSelfSignedCertificate(privateKey, cn)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Parse the PEM certificate
	if cert.Subject.CommonName != cn {
		t.Errorf("Generated certificate has incorrect common name. Expected: %s, Got: %s", cn, cert.Subject.CommonName)
	}

	// Verify that the parsed certificate's public key matches the input private key
	if !cert.PublicKey.(*rsa.PublicKey).Equal(privateKey.Public()) {
		t.Error("Parsed certificate has incorrect public key")
	}
}
