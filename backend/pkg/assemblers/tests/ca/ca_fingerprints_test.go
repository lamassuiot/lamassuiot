package ca

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"golang.org/x/crypto/sha3"
)

func expectedFingerprints(cert *x509.Certificate) models.CertificateFingerprints {
	s1 := sha1.Sum(cert.Raw)
	s256 := sha256.Sum256(cert.Raw)
	s512 := sha512.Sum512(cert.Raw)
	var s3256 [32]byte
	sha3.ShakeSum256(s3256[:], cert.Raw)
	return models.CertificateFingerprints{
		SHA1:    hex.EncodeToString(s1[:]),
		SHA256:  hex.EncodeToString(s256[:]),
		SHA512:  hex.EncodeToString(s512[:]),
		SHA3256: hex.EncodeToString(s3256[:]),
	}
}

func checkFingerprints(got models.CertificateFingerprints, cert *x509.Certificate) error {
	want := expectedFingerprints(cert)
	if got.SHA1 == "" {
		return fmt.Errorf("SHA1 fingerprint is empty")
	}
	if got.SHA256 == "" {
		return fmt.Errorf("SHA256 fingerprint is empty")
	}
	if got.SHA512 == "" {
		return fmt.Errorf("SHA512 fingerprint is empty")
	}
	if got.SHA3256 == "" {
		return fmt.Errorf("SHA3-256 fingerprint is empty")
	}
	if got.SHA1 != want.SHA1 {
		return fmt.Errorf("SHA1 mismatch: got %s, want %s", got.SHA1, want.SHA1)
	}
	if got.SHA256 != want.SHA256 {
		return fmt.Errorf("SHA256 mismatch: got %s, want %s", got.SHA256, want.SHA256)
	}
	if got.SHA512 != want.SHA512 {
		return fmt.Errorf("SHA512 mismatch: got %s, want %s", got.SHA512, want.SHA512)
	}
	if got.SHA3256 != want.SHA3256 {
		return fmt.Errorf("SHA3-256 mismatch: got %s, want %s", got.SHA3256, want.SHA3256)
	}
	return nil
}

func TestFingerprintsOnCreateCA(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)
	caDur := models.TimeDuration(time.Hour * 24)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(*models.CACertificate, error) error
	}{
		{
			name:   "OK/RSA-2048",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: issuanceDur}},
				})
				if err != nil {
					return nil, err
				}
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "fp-rsa-ca",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "FingerprintTestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
					ProfileID:    profile.ID,
				})
			},
			resultCheck: func(ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}
				x509Cert := (*x509.Certificate)(ca.Certificate.Certificate)
				return checkFingerprints(ca.Certificate.Fingerprints, x509Cert)
			},
		},
		{
			name:   "OK/ECDSA-256",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: issuanceDur}},
				})
				if err != nil {
					return nil, err
				}
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "fp-ecdsa-ca",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
					Subject:      models.Subject{CommonName: "FingerprintTestCA-EC"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
					ProfileID:    profile.ID,
				})
			},
			resultCheck: func(ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}
				x509Cert := (*x509.Certificate)(ca.Certificate.Certificate)
				return checkFingerprints(ca.Certificate.Fingerprints, x509Cert)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("BeforeEach: %s", err)
			}
			if err := tc.before(caTest.Service); err != nil {
				t.Fatalf("before: %s", err)
			}
			if err := tc.resultCheck(tc.run(caTest.HttpCASDK)); err != nil {
				t.Fatalf("unexpected result: %s", err)
			}
		})
	}
}

func TestFingerprintsOnSignCertificate(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)
	caDur := models.TimeDuration(time.Hour * 24)

	createCA := func(svc services.CAService) (*models.CACertificate, error) {
		profile, err := svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: issuanceDur}},
		})
		if err != nil {
			return nil, err
		}
		return svc.CreateCA(context.Background(), services.CreateCAInput{
			ID:           "fp-sign-ca",
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: "FingerprintSignCA"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
			ProfileID:    profile.ID,
		})
	}

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.Certificate, error)
		resultCheck func(*models.Certificate, error) error
	}{
		{
			name:   "OK/SignedCertificate",
			before: func(svc services.CAService) error { _, err := createCA(svc); return err },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}
				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "fp-test-cert"}, key)
				if err != nil {
					return nil, err
				}
				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        "fp-sign-ca",
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}
				x509Cert := (*x509.Certificate)(cert.Certificate)
				return checkFingerprints(cert.Fingerprints, x509Cert)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("BeforeEach: %s", err)
			}
			if err := tc.before(caTest.Service); err != nil {
				t.Fatalf("before: %s", err)
			}
			if err := tc.resultCheck(tc.run(caTest.HttpCASDK)); err != nil {
				t.Fatalf("unexpected result: %s", err)
			}
		})
	}
}

func TestFingerprintsOnImportCA(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(*models.CACertificate, error) error
	}{
		{
			name:   "OK/ImportSelfSignedCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				caCert, caKey, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour*10, "ImportedCA")
				if err != nil {
					return nil, err
				}
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: issuanceDur}},
				})
				if err != nil {
					return nil, err
				}
				return caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ProfileID:     profile.ID,
					Key:           caKey,
					CACertificate: (*models.X509Certificate)(caCert),
				})
			},
			resultCheck: func(ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}
				x509Cert := (*x509.Certificate)(ca.Certificate.Certificate)
				return checkFingerprints(ca.Certificate.Fingerprints, x509Cert)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("BeforeEach: %s", err)
			}
			if err := tc.before(caTest.Service); err != nil {
				t.Fatalf("before: %s", err)
			}
			if err := tc.resultCheck(tc.run(caTest.HttpCASDK)); err != nil {
				t.Fatalf("unexpected result: %s", err)
			}
		})
	}
}

func TestFingerprintsOnImportCertificate(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.Certificate, error)
		resultCheck func(*models.Certificate, error) error
	}{
		{
			name:   "OK/ImportCertificate",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				caCert, caKey, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour*10, "ImportCertCA")
				if err != nil {
					return nil, err
				}

				leafKey, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}
				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "fp-import-leaf"}, leafKey)
				if err != nil {
					return nil, err
				}
				tmpl := &x509.Certificate{
					PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
					PublicKey:          csr.PublicKey,
					SerialNumber:       big.NewInt(42),
					Issuer:             caCert.Subject,
					Subject:            csr.Subject,
					NotBefore:          time.Now(),
					NotAfter:           time.Now().Add(time.Hour),
					KeyUsage:           x509.KeyUsageDigitalSignature,
				}
				certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
				if err != nil {
					return nil, err
				}
				leafCert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					return nil, err
				}

				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: issuanceDur}},
				})
				if err != nil {
					return nil, err
				}
				if _, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ProfileID:     profile.ID,
					Key:           caKey,
					CACertificate: (*models.X509Certificate)(caCert),
				}); err != nil {
					return nil, err
				}

				return caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: (*models.X509Certificate)(leafCert),
					Metadata:    map[string]any{},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}
				x509Cert := (*x509.Certificate)(cert.Certificate)
				return checkFingerprints(cert.Fingerprints, x509Cert)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("BeforeEach: %s", err)
			}
			if err := tc.before(caTest.Service); err != nil {
				t.Fatalf("before: %s", err)
			}
			if err := tc.resultCheck(tc.run(caTest.HttpCASDK)); err != nil {
				t.Fatalf("unexpected result: %s", err)
			}
		})
	}
}
