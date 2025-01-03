package x509engines

import (
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	cmodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
)

func setup(t *testing.T) (string, cryptoengines.CryptoEngine, X509Engine) {
	filesystem.Register()

	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a new instance of GoCryptoEngine
	log := chelpers.SetupLogger(config.Info, "Test Case", "Golang Engine")
	conf := config.CryptoEngineConfig{
		ID:       "test-engine",
		Type:     config.FilesystemProvider,
		Metadata: map[string]interface{}{},
		Config: map[string]interface{}{
			"storage_directory": tempDir,
		},
	}

	builder := cryptoengines.GetEngineBuilder(config.FilesystemProvider)

	engine, _ := builder(log, conf)

	x509Engine := NewX509Engine(log, &engine, "ocsp.lamassu.io")

	return tempDir, engine, x509Engine
}

func teardown(tempDir string) {
	// Remove the temporary directory
	os.RemoveAll(tempDir)
}

func TestGetCACryptoSigner(t *testing.T) {
	tempDir, engine, x509Engine := setup(t)
	defer teardown(tempDir)
	caCertificate, key, err := chelpers.GenerateSelfSignedCA(x509.RSA, 365*24*time.Hour, "MyCA")
	if err != nil {
		t.Fatalf("failed to generate self signed CA: %s", err)
	}

	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("private key is not of type rsa.PrivateKey")
	}

	_, importedSigner, err := engine.ImportRSAPrivateKey(rsaPrivateKey)
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
	caCertificate, _, err := chelpers.GenerateSelfSignedCA(x509.RSA, 365*24*time.Hour, "MyCA")
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

func checkCertificate(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyType, tcExpirationTime time.Time) error {
	if cert.Subject.CommonName != tcSubject.CommonName {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
	}

	if cert.Subject.Organization[0] != tcSubject.Organization {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Organization, tcSubject.Organization)
	}

	if cert.Subject.OrganizationalUnit[0] != tcSubject.OrganizationUnit {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.OrganizationalUnit, tcSubject.OrganizationUnit)
	}

	if cert.Subject.Country[0] != tcSubject.Country {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Country, tcSubject.Country)
	}

	if cert.Subject.Province[0] != tcSubject.State {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Province, tcSubject.State)
	}

	if cert.Subject.Locality[0] != tcSubject.Locality {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.Locality, tcSubject.Locality)
	}

	if cmodels.KeyType(cert.PublicKeyAlgorithm) != tcKeyMetadata {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.PublicKeyAlgorithm, tcKeyMetadata)
	}

	if !cert.NotAfter.Equal(tcExpirationTime.UTC().Truncate(time.Second)) {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.NotAfter, tcExpirationTime.UTC().Truncate(time.Minute))
	}
	return nil
}

func checkCACertificate(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, tcExpirationTime time.Time) error {

	err := checkCertificate(cert, tcSubject, tcKeyMetadata.Type, tcExpirationTime)
	if err != nil {
		return err
	}

	if cert.IsCA != true {
		return fmt.Errorf("unexpected result, got: %t, want: %t", cert.IsCA, true)
	}

	if cert.OCSPServer[0] != "https://ocsp.lamassu.io/ocsp" {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.OCSPServer, "https://ocsp.lamassuiot.com/ocsp")
	}

	if cert.CRLDistributionPoints[0] != "https://ocsp.lamassu.io/crl/"+string(cert.SubjectKeyId) {
		return fmt.Errorf("unexpected result, got: %s, want: %s", cert.CRLDistributionPoints, "https://crl.lamassuiot.com/crl/"+string(cert.SubjectKeyId))
	}
	return nil
}

func TestCreateRootCA(t *testing.T) {

	tempDir, _, x509Engine := setup(t)
	defer teardown(tempDir)

	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	checkOk := func(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, tcExpirationTime time.Time, err error) error {
		if err != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		return checkCACertificate(cert, tcSubject, tcKeyMetadata, tcExpirationTime)
	}

	checkFail := func(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, tcExpirationTime time.Time, err error) error {
		if err == nil {
			return fmt.Errorf("expected error, got nil")
		}
		return nil
	}

	caSubject := cmodels.Subject{
		CommonName:       "Root CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	var testcases = []struct {
		name           string
		caId           string
		subject        cmodels.Subject
		keyMetadata    cmodels.KeyMetadata
		expirationTime time.Time
		check          func(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, expirationTime time.Time, err error) error
	}{
		{
			name:    "OK/RSA_2048",
			caId:    "rootCA-RSA2048",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "FAIL/RSA_1",
			caId:    "rootCA-RSA1",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.RSA),
				Bits: 1,
			},
			expirationTime: expirationTime,
			check:          checkFail,
		},
		{
			name:    "OK/ECDSA_256",
			caId:    "rootCA-ECDSA_256",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/ECDSA_224",
			caId:    "rootCA-ECDSA_224",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 224,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/ECDSA_384",
			caId:    "rootCA-ECDSA_384",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 384,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "OK/ECDSA_521",
			caId:    "rootCA-ECDSA_521",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 521,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{
			name:    "FAIL/ECDSA_NOT_SUPORTED",
			caId:    "rootCA-ECDSA_FAIL",
			subject: caSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
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
			_, cert, err := x509Engine.CreateRootCA(tc.keyMetadata, tc.subject, tc.expirationTime)
			err = tc.check(cert, tc.subject, tc.keyMetadata, tc.expirationTime, err)
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

	keyMetadata := cmodels.KeyMetadata{
		Type: cmodels.KeyType(x509.RSA),
		Bits: 2048,
	}

	subject := cmodels.Subject{
		CommonName:       "Root CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now
	logger := chelpers.SetupLogger(config.Info, "Test Case", "Golang Engine")

	// Call the CreateRootCA method
	_, rootCaCertRSA, err := x509Engine.CreateRootCA(keyMetadata, subject, expirationTime)
	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	keyMetadata = cmodels.KeyMetadata{
		Type: cmodels.KeyType(x509.ECDSA),
		Bits: 256,
	}

	// Call the CreateRootCA method
	_, rootCaCertEC, err := x509Engine.CreateRootCA(keyMetadata, subject, expirationTime)
	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	caCertificateNotImported, _, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, 365*24*time.Hour, "MyCA")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	subordinateSubject := cmodels.Subject{
		CommonName:       "Subordinate CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	checkOk := func(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, tcExpirationTime time.Time, err error) error {
		// Verify the result
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		return checkCACertificate(cert, tcSubject, tcKeyMetadata, tcExpirationTime)
	}

	checkFail := func(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, tcExpirationTime time.Time, err error) error {
		if err == nil {
			return fmt.Errorf("expected error, got nil")
		}
		return nil
	}

	var testcases = []struct {
		name            string
		subordinateCAID string
		rootCaCert      *x509.Certificate
		subject         cmodels.Subject
		keyMetadata     cmodels.KeyMetadata
		expirationTime  time.Time
		check           func(cert *x509.Certificate, tcSubject cmodels.Subject, tcKeyMetadata cmodels.KeyMetadata, tcExpirationTime time.Time, err error) error
	}{
		{name: "OK/RSA_RSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertRSA,
			subject:         subordinateSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/RSA_EC",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertRSA,
			subject:         subordinateSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_RSA",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEC,
			subject:         subordinateSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.RSA),
				Bits: 2048,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "OK/EC_EC",
			subordinateCAID: "subCA",
			rootCaCert:      rootCaCertEC,
			subject:         subordinateSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkOk,
		},
		{name: "FAIL/ROOT_CA_NOT_FOUND",
			subordinateCAID: "subCA",
			rootCaCert:      caCertificateNotImported,
			subject:         subordinateSubject,
			keyMetadata: cmodels.KeyMetadata{
				Type: cmodels.KeyType(x509.ECDSA),
				Bits: 256,
			},
			expirationTime: expirationTime,
			check:          checkFail,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			aki, err := software.NewSoftwareCryptoEngine(logger).EncodePKIXPublicKeyDigest(tc.rootCaCert.PublicKey)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			// Call the CreateSubordinateCA method
			_, cert, err := x509Engine.CreateSubordinateCA(aki, tc.rootCaCert, tc.keyMetadata, tc.subject, tc.expirationTime, x509Engine)
			err = tc.check(cert, tc.subject, tc.keyMetadata, tc.expirationTime, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})

	}
}

func TestSignCertificateRequest(t *testing.T) {
	tempDir, _, x509Engine := setup(t)
	defer teardown(tempDir)

	keyMetadata := cmodels.KeyMetadata{
		Type: cmodels.KeyType(x509.RSA),
		Bits: 2048,
	}

	subject := cmodels.Subject{
		CommonName: "Root CA",
	}
	expirationTime := time.Now().AddDate(1, 0, 0) // Set expiration time to 1 year from now

	// Call the CreateRootCA method
	_, caCertificateRSA, err := x509Engine.CreateRootCA(keyMetadata, subject, expirationTime)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	keyMetadata = cmodels.KeyMetadata{
		Type: cmodels.KeyType(x509.ECDSA),
		Bits: 256,
	}

	_, caCertificateEC, err := x509Engine.CreateRootCA(keyMetadata, subject, expirationTime)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	caCertificateNotImported, _, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, 365*24*time.Hour, "MyCA")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	csrSubject := cmodels.Subject{
		CommonName:       "Subordinate CA",
		Organization:     "Lamassu IoT",
		OrganizationUnit: "CA",
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
	}

	checkOk := func(cert *x509.Certificate, tcSubject cmodels.Subject, keyType cmodels.KeyType, expirationTime time.Time, errCsr error, errSign error) error {

		if errCsr != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		if errSign != nil {
			return fmt.Errorf("unexpected error: %s", err)
		}

		err := checkCertificate(cert, tcSubject, keyType, expirationTime)
		if err != nil {
			return err
		}

		if cert.Subject.CommonName != tcSubject.CommonName {
			return fmt.Errorf("unexpected result, got: %s, want: %s", cert.Subject.CommonName, tcSubject.CommonName)
		}
		return nil
	}

	checkFail := func(cert *x509.Certificate, tcSubject cmodels.Subject, keyType cmodels.KeyType, expirationTime time.Time, errCsr error, errSign error) error {
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
		subject       cmodels.Subject
		extensions    func() []pkix.Extension
		keyType       cmodels.KeyType
		key           func() any
		check         func(cert *x509.Certificate, tcSubject cmodels.Subject, keyType cmodels.KeyType, expirationTime time.Time, errCsr error, errSign error) error
	}{
		{
			name:          "OK/RSA_RSA",
			caCertificate: caCertificateRSA,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       cmodels.KeyType(x509.RSA),
			key: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_RSA",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       cmodels.KeyType(x509.RSA),
			key: func() any {
				key, _ := chelpers.GenerateRSAKey(2048)
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/RSA_EC",
			caCertificate: caCertificateRSA,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       cmodels.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EC_EC",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			keyType:       cmodels.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkOk,
		},
		{
			name:          "OK/EXT_SAN",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			extensions: func() []pkix.Extension {
				rawValues := []asn1.RawValue{}
				// nameTypeEmail = 1
				// nameTypeURI = 6
				nameTypeDNS := 2 //RFC 5280 > Section 4.2.1.6 https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
				nameTypeIP := 7

				ip := net.IP{192, 168, 10, 1}
				rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte("dev.lamassu.io")})
				rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip.To4()})
				val, _ := asn1.Marshal(rawValues)

				return []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // Subject Alternative Name OID
					Value: val,
				}}
			},
			keyType: cmodels.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: func(cert *x509.Certificate, tcSubject cmodels.Subject, keyType cmodels.KeyType, expirationTime time.Time, errCsr, errSign error) error {
				if err := checkOk(cert, tcSubject, keyType, expirationTime, errCsr, errSign); err != nil {
					return nil
				}

				if len(cert.IPAddresses) != 1 {
					return fmt.Errorf("expected 1 SAN IP address, got %d", len(cert.IPAddresses))
				}

				expectedIP := net.IP{192, 168, 10, 1}
				if !cert.IPAddresses[0].Equal(expectedIP) {
					return fmt.Errorf("IP address mismatch. Expected %s, got %s", cert.IPAddresses[0].String(), expectedIP.String())
				}

				if len(cert.DNSNames) != 1 {
					return fmt.Errorf("expected 1 SAN DNS name, got %d", len(cert.DNSNames))
				}

				if cert.DNSNames[0] != "dev.lamassu.io" {
					return fmt.Errorf("DNS name mismatch. Expected dev.lamassu.io, got %s", cert.DNSNames[0])
				}

				return nil
			},
		},
		{
			name:          "OK/KEY_USAGE",
			caCertificate: caCertificateEC,
			subject:       csrSubject,
			keyType:       cmodels.KeyType(x509.ECDSA),
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			extensions: func() []pkix.Extension { return []pkix.Extension{} },
			check: func(cert *x509.Certificate, tcSubject cmodels.Subject, keyType cmodels.KeyType, expirationTime time.Time, errCsr, errSign error) error {
				if err := checkOk(cert, tcSubject, keyType, expirationTime, errCsr, errSign); err != nil {
					return nil
				}

				if cert.KeyUsage != x509.KeyUsageDigitalSignature {
					return fmt.Errorf("missing key 'KeyUsageDigitalSignature' usage")
				}

				expectedKeyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				for _, expectedKeyUsage := range expectedKeyUsages {
					if contains := slices.Contains(cert.ExtKeyUsage, expectedKeyUsage); !contains {
						return fmt.Errorf("missing key usage %d in signed cert", expectedKeyUsage)
					}
				}

				return nil
			},
		},
		{
			name:          "FAIL/NOT_EXISTENT_CA",
			caCertificate: caCertificateNotImported,
			subject:       csrSubject,
			keyType:       cmodels.KeyType(x509.ECDSA),
			extensions:    func() []pkix.Extension { return []pkix.Extension{} },
			key: func() any {
				key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				return key
			},
			check: checkFail,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			csr, errCsr := chelpers.GenerateCertificateRequestWithExtensions(tc.subject, tc.extensions(), tc.key())
			cert, errSing := x509Engine.SignCertificateRequest(tc.caCertificate, csr, expirationTime)
			err := tc.check(cert, tc.subject, tc.keyType, expirationTime, errCsr, errSing)
			if err != nil {
				t.Errorf("unexpected result in test case: %s", err)
			}
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
