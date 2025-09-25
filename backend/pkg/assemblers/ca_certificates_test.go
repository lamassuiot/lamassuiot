package assemblers

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestDeleteCertificateSDK(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(caSDK services.CAService) (string, string, error) // returns certificateSerialNumber, caID, error
		run         func(caSDK services.CAService, certSerialNumber string) error
		resultCheck func(err error) error
	}{
		{
			name: "OK/DeleteCertificate_IssuerCANotExists",
			before: func(caSDK services.CAService) (string, string, error) {
				// Create CA and certificate
				ca, cert, err := createCAAndCertificate(caSDK)
				if err != nil {
					return "", "", err
				}

				// Expire the CA first so it can be deleted
				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:   ca.ID,
					Status: models.StatusExpired,
				})
				if err != nil {
					return "", "", err
				}

				// Delete the CA to make the certificate orphaned
				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID: ca.ID,
				})
				if err != nil {
					return "", "", err
				}

				return cert.SerialNumber, ca.ID, nil
			},
			run: func(caSDK services.CAService, certSerialNumber string) error {
				return caSDK.DeleteCertificate(context.Background(), services.DeleteCertificateInput{
					SerialNumber: certSerialNumber,
				})
			},
			resultCheck: func(err error) error {
				if err != nil {
					return err
				}
				return nil
			},
		},
		{
			name: "ERR/DeleteCertificate_IssuerCAExists",
			before: func(caSDK services.CAService) (string, string, error) {
				// Create CA and certificate but don't delete the CA
				ca, cert, err := createCAAndCertificate(caSDK)
				if err != nil {
					return "", "", err
				}

				return cert.SerialNumber, ca.ID, nil
			},
			run: func(caSDK services.CAService, certSerialNumber string) error {
				return caSDK.DeleteCertificate(context.Background(), services.DeleteCertificateInput{
					SerialNumber: certSerialNumber,
				})
			},
			resultCheck: func(err error) error {
				if err == errs.ErrCertificateIssuerCAExists {
					return nil // This is expected
				}
				if err == nil {
					return fmt.Errorf("expected ErrCertificateIssuerCAExists error but got none")
				}
				return err
			},
		},
		{
			name: "ERR/DeleteCertificate_CertificateNotFound",
			before: func(caSDK services.CAService) (string, string, error) {
				// Return a non-existent certificate serial number
				return "non-existent-cert-serial", "", nil
			},
			run: func(caSDK services.CAService, certSerialNumber string) error {
				return caSDK.DeleteCertificate(context.Background(), services.DeleteCertificateInput{
					SerialNumber: certSerialNumber,
				})
			},
			resultCheck: func(err error) error {
				if err == errs.ErrCertificateNotFound {
					return nil // This is expected
				}
				if err == nil {
					return fmt.Errorf("expected ErrCertificateNotFound error but got none")
				}
				return err
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			certSerialNumber, _, err := testcase.before(caTest.HttpCASDK)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = testcase.resultCheck(testcase.run(caTest.HttpCASDK, certSerialNumber))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestDeleteCertificateService(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(caSDK services.CAService) (string, string, error) // returns certificateSerialNumber, caID, error
		run         func(caSDK services.CAService, certSerialNumber string) error
		resultCheck func(err error) error
	}{
		{
			name: "ERR/DeleteCertificate_ValidationError",
			before: func(caSDK services.CAService) (string, string, error) {
				// Return empty serial number to trigger validation error
				return "", "", nil
			},
			run: func(caSDK services.CAService, certSerialNumber string) error {
				return caSDK.DeleteCertificate(context.Background(), services.DeleteCertificateInput{
					SerialNumber: certSerialNumber,
				})
			},
			resultCheck: func(err error) error {
				if err == errs.ErrValidateBadRequest {
					return nil // This is expected
				}
				if err == nil {
					return fmt.Errorf("expected ErrValidateBadRequest error but got none")
				}
				return err
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			certSerialNumber, _, err := testcase.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = testcase.resultCheck(testcase.run(caTest.Service, certSerialNumber))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestSignCertificateWithDefaultProfile(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Create CA
	ca, _, err := createCAAndCertificate(caTest.HttpCASDK)
	if err != nil {
		t.Fatalf("failed to create CA and certificate: %s", err)
	}
	// Generate key and CSR for certificate
	key, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %s", err)
	}

	csr, err := chelpers.GenerateCertificateRequest(
		models.Subject{
			CommonName:       "test-cert",
			Country:          "ES",
			Organization:     "lamassu",
			OrganizationUnit: "iot",
			State:            "lamassu-world",
			Locality:         "lamassu-city",
		},
		key,
	)
	if err != nil {
		t.Fatalf("failed to generate CSR: %s", err)
	}

	cert, err := caTest.HttpCASDK.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:        ca.ID,
		CertRequest: (*models.X509CertificateRequest)(csr),
	})
	if err != nil {
		t.Fatalf("failed to sign certificate: %s", err)
	}

	// Check certificate validity
	if cert.Subject.CommonName != "test-cert" {
		t.Errorf("expected CommonName 'test-cert', got '%s'", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "TestCA" {
		t.Errorf("expected Issuer CommonName 'TestCA', got '%s'", cert.Issuer.CommonName)
	}

	// Default profile duration is 12 hours
	expectedDuration := 12 * time.Hour
	actualDuration := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
	if actualDuration != expectedDuration {
		t.Errorf("expected certificate duration %s, got %s", expectedDuration, actualDuration)
	}

}

// Helper function to create a CA and issue a certificate
func createCAAndCertificate(caSDK services.CAService) (*models.CACertificate, *models.Certificate, error) {
	caDur := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

	// Create issuance profile
	profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// Create CA
	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "TestCA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
		ProfileID:    profile.ID,
	})
	if err != nil {
		return nil, nil, err
	}

	// Generate key and CSR for certificate
	key, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		return nil, nil, err
	}

	csr, err := chelpers.GenerateCertificateRequest(
		models.Subject{
			CommonName:       "test-cert",
			Country:          "ES",
			Organization:     "lamassu",
			OrganizationUnit: "iot",
			State:            "lamassu-world",
			Locality:         "lamassu-city",
		},
		key,
	)
	if err != nil {
		return nil, nil, err
	}

	// Sign certificate with the CA (CA is already active by default)
	cert, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:        ca.ID,
		CertRequest: (*models.X509CertificateRequest)(csr),
		IssuanceProfile: &models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	return ca, cert, nil
}
