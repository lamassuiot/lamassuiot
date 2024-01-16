package x509engines

import (
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
)

func setup(t *testing.T) (string, cryptoengines.CryptoEngine, X509Engine) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a new instance of GoCryptoEngine
	log := helpers.ConfigureLogger(config.Info, "Golang Engine")
	engine := cryptoengines.NewGolangPEMEngine(log, config.GolangEngineConfig{StorageDirectory: tempDir})

	x509Engine := NewX509Engine(&engine, "")

	return tempDir, engine, x509Engine
}

func teardown(tempDir string) {
	// Remove the temporary directory
	os.RemoveAll(tempDir)
}

func TestGetCACryptoSigner(t *testing.T) {
	tempDir, engine, x509Engine := setup(t)
	defer teardown(tempDir)
	caCertificate, key, err := helpers.GenerateSelfSignedCA(x509.RSA, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate self signed CA: %s", err)
	}

	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("private key is not of type rsa.PrivateKey")
	}

	importedSigner, err := engine.ImportRSAPrivateKey(rsaPrivateKey, helpers.SerialNumberToString(caCertificate.SerialNumber))
	if err != nil {
		t.Fatalf("failed to import private key: %s", err)
	}

	// Call the GetCACryptoSigner method
	signer, err := x509Engine.GetCACryptoSigner(caCertificate)

	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if !reflect.DeepEqual(signer.Public(), caCertificate.PublicKey) {
		t.Error("Public key does not match to the certificates public key")
	}

	if !reflect.DeepEqual(signer.Public(), importedSigner.Public()) {
		t.Error("Public key does not match to the imported signer public key")
	}

}

func TestGetCACryptoSignerNonExistentKey(t *testing.T) {
	tempDir, _, x509Engine := setup(t)
	defer teardown(tempDir)
	caCertificate, _, err := helpers.GenerateSelfSignedCA(x509.RSA, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate self signed CA: %s", err)
	}

	// Call the GetCACryptoSigner method
	signer, err := x509Engine.GetCACryptoSigner(caCertificate)

	// Verify the result
	if err == nil {
		t.Error("expected an error, but got nil")
	}

	if signer != nil {
		t.Error("expected signer to be nil, but got non-nil value")
	}
}

func TestCryptoAssetLRI(t *testing.T) {
	cryptoAssetType := CryptoAssetType("sample")
	keyID := "12345"

	expected := "lms-caservice-sample-keyid-12345"
	result := CryptoAssetLRI(cryptoAssetType, keyID)

	if result != expected {
		t.Errorf("unexpected result, got: %s, want: %s", result, expected)
	}

	cryptoAssetType = Certificate
	expected = "lms-caservice-cert-keyid-12345"
	result = CryptoAssetLRI(cryptoAssetType, keyID)

	if result != expected {
		t.Errorf("unexpected result, got: %s, want: %s", result, expected)
	}

	cryptoAssetType = CertificateAuthority
	expected = "lms-caservice-certauth-keyid-12345"
	result = CryptoAssetLRI(cryptoAssetType, keyID)

	if result != expected {
		t.Errorf("unexpected result, got: %s, want: %s", result, expected)
	}
}

func TestCreateRootCA(t *testing.T) {

	tempDir, _, x509Engine := setup(t)
	defer teardown(tempDir)

	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	checkOk := func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, err error) error {
		if err != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		if cert.Subject.CommonName != tcSubject.CommonName {
			return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
		}
		return nil
	}

	checkFail := func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, err error) error {
		if err == nil {
			return fmt.Errorf("expected error, got nil")
		}
		return nil
	}

	var testcases = []struct {
		name           string
		caId           string
		subject        models.Subject
		keyMetadata    models.KeyMetadata
		expirationTime time.Time
		check          func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, err error) error
	}{
		{
			name: "OK/RSA_2048",
			caId: "rootCA-RSA2048",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name: "FAIL/RSA_1",
			caId: "rootCA-RSA1",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 1,
			},
			expirationTime: expirationTime,
			check:          checkFail,
		},
		{
			name: "OK/ECDSA_256",
			caId: "rootCA-ECDSA_256",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name: "OK/ECDSA_224",
			caId: "rootCA-ECDSA_224",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 224,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name: "OK/ECDSA_384",
			caId: "rootCA-ECDSA_384",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 384,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name: "OK/ECDSA_521",
			caId: "rootCA-ECDSA_521",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 521,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name: "FAIL/ECDSA_NOT_SUPORTED",
			caId: "rootCA-ECDSA_FAIL",
			subject: models.Subject{
				CommonName: "Root CA",
			},
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 1024,
			},
			expirationTime: expirationTime,
			check:          checkFail,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// Call the CreateRootCA method
			cert, err := x509Engine.CreateRootCA(tc.caId, tc.keyMetadata, tc.subject, tc.expirationTime)
			err = tc.check(cert, tc.subject, tc.keyMetadata, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)

			}
		})

	}
}

func TestCreateSubordinateCA(t *testing.T) {
	// Setup
	tempDir, _, x509Engine := setup(t)
	defer teardown(tempDir)

	caID := "rootCA"
	keyMetadata := models.KeyMetadata{
		Type: models.KeyType(x509.RSA),
		Bits: 2048,
	}
	subject := models.Subject{
		CommonName: "Root CA",
	}
	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	// Call the CreateRootCA method
	rootCaCertRSA, err := x509Engine.CreateRootCA(caID, keyMetadata, subject, expirationTime)
	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	keyMetadata = models.KeyMetadata{
		Type: models.KeyType(x509.ECDSA),
		Bits: 256,
	}

	// Call the CreateRootCA method
	rootCaCertEC, err := x509Engine.CreateRootCA(caID, keyMetadata, subject, expirationTime)
	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	subordinateSubject := models.Subject{
		CommonName: "Subordinate CA",
	}

	checkOk := func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, err error) error {
		// Verify the result
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if cert.Subject.CommonName != tcSubject.CommonName {
			t.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
		}
		return nil
	}

	var testcases = []struct {
		name            string
		subordinateCAID string
		aki             string
		rootCaCert      *x509.Certificate
		subject         models.Subject
		keyMetadata     models.KeyMetadata
		expirationTime  time.Time
		check           func(cert *x509.Certificate, tcSubject models.Subject, tcKeyMetadata models.KeyMetadata, err error) error
	}{
		{name: "OK/RSA_RSA",
			subordinateCAID: "subCA",
			aki:             "12345",
			rootCaCert:      rootCaCertRSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/RSA_EC",
			subordinateCAID: "subCA",
			aki:             "12345",
			rootCaCert:      rootCaCertRSA,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_RSA",
			subordinateCAID: "subCA",
			aki:             "12345",
			rootCaCert:      rootCaCertEC,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_EC",
			subordinateCAID: "subCA",
			aki:             "12345",
			rootCaCert:      rootCaCertEC,
			subject:         subordinateSubject,
			keyMetadata: models.KeyMetadata{
				Type: models.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			// Call the CreateSubordinateCA method
			cert, err := x509Engine.CreateSubordinateCA(tc.aki, tc.subordinateCAID, tc.rootCaCert, tc.keyMetadata, tc.subject, tc.expirationTime, x509Engine)
			err = tc.check(cert, tc.subject, tc.keyMetadata, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})

	}
}

func TestSignCertificateRequest(t *testing.T) {

	tempDir, _, x509Engine := setup(t)
	defer teardown(tempDir)

	caID := "rootCA"
	keyMetadata := models.KeyMetadata{
		Type: models.KeyType(x509.RSA),
		Bits: 2048,
	}
	subject := models.Subject{
		CommonName: "Root CA",
	}
	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	// Call the CreateRootCA method
	caCertificateRSA, err := x509Engine.CreateRootCA(caID, keyMetadata, subject, expirationTime)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	keyMetadata = models.KeyMetadata{
		Type: models.KeyType(x509.ECDSA),
		Bits: 256,
	}

	caCertificateEC, err := x509Engine.CreateRootCA(caID, keyMetadata, subject, expirationTime)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	caCertificateNotImported, _, err := helpers.GenerateSelfSignedCA(x509.ECDSA, 365*24*time.Hour)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	csrSubject := models.Subject{
		CommonName:       "example.com",
		Organization:     "Acme Inc",
		OrganizationUnit: "IT",
	}

	checkOk := func(cert *x509.Certificate, tcSubject models.Subject, errCsr error, errSign error) error {

		if errCsr != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		if errSign != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		if cert.Subject.CommonName != tcSubject.CommonName {
			return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
		}
		return nil
	}

	checkFail := func(cert *x509.Certificate, tcSubject models.Subject, errCsr error, errSign error) error {
		if errCsr != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}
		if errSign == nil {
			return fmt.Errorf("expected error, got nil")
		}
		return nil
	}

	var testcases = []struct {
		name          string
		caCertificate *x509.Certificate
		subject       models.Subject
		key           func() any
		check         func(cert *x509.Certificate, tcSubject models.Subject, errCsr error, errSign error) error
	}{
		{
			name:          "OK/RSA_RSA",
			caCertificate: caCertificateRSA,
			subject:       csrSubject,
			key: func() any {
				key, _ := helpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_RSA",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			key: func() any {
				key, _ := helpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/RSA_EC",
			caCertificate: caCertificateRSA,
			subject:       csrSubject,
			key: func() any {
				key, _ := helpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_EC",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			key: func() any {
				key, _ := helpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "FAIL/NOT_EXISTENT_CA",
			caCertificate: caCertificateNotImported,
			subject:       csrSubject,
			key: func() any {
				key, _ := helpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkFail,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			csr, errCsr := helpers.GenerateCertificateRequest(tc.subject, tc.key())
			cert, errSing := x509Engine.SignCertificateRequest(tc.caCertificate, csr, expirationTime)
			tc.check(cert, tc.subject, errCsr, errSing)
		})
	}
}

func TestGetEngineConfig(t *testing.T) {
	tempDir, engine, x509Engine := setup(t)
	defer teardown(tempDir)

	// Call the GetEngineConfig method
	config := x509Engine.GetEngineConfig()

	// Verify the result
	expected := engine.GetEngineConfig()
	if !reflect.DeepEqual(config, expected) {
		t.Errorf("unexpected result, got: %v, want: %v", config, expected)
	}
}
