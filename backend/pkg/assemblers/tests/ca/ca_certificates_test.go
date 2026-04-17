package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestDeleteCertificateSDK(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
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
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
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
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
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

func createCertificateWithExtensions(t *testing.T, caSDK services.CAService, caID string, commonName string, keyUsage x509.KeyUsage, extendedKeyUsage []x509.ExtKeyUsage) *models.Certificate {
	t.Helper()

	profileExtendedKeyUsage := make([]models.X509ExtKeyUsage, 0, len(extendedKeyUsage))
	for _, usage := range extendedKeyUsage {
		profileExtendedKeyUsage = append(profileExtendedKeyUsage, models.X509ExtKeyUsage(usage))
	}

	cert, err := caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
		CAID: caID,
		KeySpec: services.CertificateKeySpec{
			Type: models.KeyType(x509.RSA),
			Bits: 2048,
		},
		Subject: models.Subject{CommonName: commonName},
		IssuanceProfile: &models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)},

			HonorSubject: true,

			HonorKeyUsage: false,
			KeyUsage:      models.X509KeyUsage(keyUsage),

			HonorExtendedKeyUsages: false,
			ExtendedKeyUsages:      profileExtendedKeyUsage,
		},
	})
	if err != nil {
		t.Fatalf("failed to create certificate %s: %s", commonName, err)
	}

	return cert
}

func TestGetCertificatesFilterBySubjectKeyID(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Ensure clean DB and init CA
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running BeforeEach: %s", err)
	}
	_, err = initCA(caTest.Service)
	if err != nil {
		t.Fatalf("failed to init CA: %s", err)
	}

	// Create two CAs and issue a certificate each (ensure SKIs differ)
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create first CA and certificate: %s", err)
	}

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create second CA and certificate: %s", err)
	}

	if cert1.SubjectKeyID == cert2.SubjectKeyID {
		t.Fatalf("expected different SKIs for the two test certificates, got equal: %s", cert1.SubjectKeyID)
	}
	if err != nil {
		t.Fatalf("failed to create CA and certificate: %s", err)
	}

	// Query certificates filtering by subject_key_id
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "subject_key_id",
				Value:           cert1.SubjectKeyID,
				FilterOperation: resources.StringEqual,
			},
		},
	}

	_, err = caTest.HttpCASDK.GetCertificates(context.Background(), services.GetCertificatesInput{
		ListInput: resources.ListInput[models.Certificate]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Certificate) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetCertificates returned error: %s", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 certificate filtered by subject_key_id, got %d", len(found))
	}

	if found[0].SerialNumber != cert1.SerialNumber {
		t.Fatalf("expected certificate serial %s, got %s", cert1.SerialNumber, found[0].SerialNumber)
	}

	if found[0].SubjectKeyID != cert1.SubjectKeyID {
		t.Fatalf("expected subject_key_id %s, got %s", cert1.SubjectKeyID, found[0].SubjectKeyID)
	}
}

func TestGetCertificatesFilterBySubjectKeyIDNotIn(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Ensure clean DB and init CA
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running BeforeEach: %s", err)
	}
	_, err = initCA(caTest.Service)
	if err != nil {
		t.Fatalf("failed to init CA: %s", err)
	}

	// Create three CAs and issue a certificate each
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create first CA and certificate: %s", err)
	}

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create second CA and certificate: %s", err)
	}

	_, cert3, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create third CA and certificate: %s", err)
	}

	// Query certificates excluding cert1 and cert2 using NotIn filter
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "subject_key_id",
				Value:           cert1.SubjectKeyID + "," + cert2.SubjectKeyID,
				FilterOperation: resources.StringNotIn,
			},
		},
	}

	_, err = caTest.HttpCASDK.GetCertificates(context.Background(), services.GetCertificatesInput{
		ListInput: resources.ListInput[models.Certificate]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Certificate) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetCertificates returned error: %s", err)
	}

	// Should only find cert3 (and the original init certificate from initCA)
	// At minimum, cert3 should be in the results and cert1, cert2 should not
	foundCert3 := false
	for _, cert := range found {
		if cert.SubjectKeyID == cert1.SubjectKeyID || cert.SubjectKeyID == cert2.SubjectKeyID {
			t.Fatalf("certificate with excluded subject_key_id was found in results: %s", cert.SubjectKeyID)
		}
		if cert.SubjectKeyID == cert3.SubjectKeyID {
			foundCert3 = true
		}
	}

	if !foundCert3 {
		t.Fatalf("expected to find cert3 with subject_key_id %s in not-in filtered results", cert3.SubjectKeyID)
	}
}

func TestGetCertificatesFilterBySubjectKeyIDNotInIgnoreCase(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Ensure clean DB and init CA
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running BeforeEach: %s", err)
	}
	_, err = initCA(caTest.Service)
	if err != nil {
		t.Fatalf("failed to init CA: %s", err)
	}

	// Create three CAs and issue a certificate each
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create first CA and certificate: %s", err)
	}

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create second CA and certificate: %s", err)
	}

	_, cert3, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create third CA and certificate: %s", err)
	}

	// Query certificates excluding cert1 and cert2 using NotInIgnoreCase filter
	// Note: We uppercase the filter values to test case-insensitivity
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "subject_key_id",
				Value:           strings.ToUpper(cert1.SubjectKeyID) + "," + strings.ToUpper(cert2.SubjectKeyID),
				FilterOperation: resources.StringNotInIgnoreCase,
			},
		},
	}

	_, err = caTest.HttpCASDK.GetCertificates(context.Background(), services.GetCertificatesInput{
		ListInput: resources.ListInput[models.Certificate]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Certificate) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetCertificates returned error: %s", err)
	}

	// Should only find cert3 (and the original init certificate from initCA)
	// At minimum, cert3 should be in the results and cert1, cert2 should not
	foundCert3 := false
	for _, cert := range found {
		if strings.ToLower(cert.SubjectKeyID) == strings.ToLower(cert1.SubjectKeyID) ||
			strings.ToLower(cert.SubjectKeyID) == strings.ToLower(cert2.SubjectKeyID) {
			t.Fatalf("certificate with excluded subject_key_id was found in results: %s", cert.SubjectKeyID)
		}
		if cert.SubjectKeyID == cert3.SubjectKeyID {
			foundCert3 = true
		}
	}

	if !foundCert3 {
		t.Fatalf("expected to find cert3 with subject_key_id %s in not-in-ignorecase filtered results", cert3.SubjectKeyID)
	}
}

func TestGetCertificatesFilterByExtensionKeyUsage(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running BeforeEach: %s", err)
	}

	ca := createActiveCA(t, caTest.HttpCASDK)

	cert1 := createCertificateWithExtensions(t, caTest.HttpCASDK, ca.ID, "ku-digital-signature", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	cert2 := createCertificateWithExtensions(t, caTest.HttpCASDK, ca.ID, "ku-key-encipherment", x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	cert3 := createCertificateWithExtensions(t, caTest.HttpCASDK, ca.ID, "ku-both", x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "extensions.key_usage",
				Value:           "DigitalSignature",
				FilterOperation: resources.StringArrayContains,
			},
		},
	}

	_, err = caTest.HttpCASDK.GetCertificates(context.Background(), services.GetCertificatesInput{
		ListInput: resources.ListInput[models.Certificate]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Certificate) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetCertificates returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 certificates filtered by key usage, got %d", len(found))
	}

	foundSerials := map[string]bool{}
	for _, cert := range found {
		foundSerials[cert.SerialNumber] = true
	}

	if !foundSerials[cert1.SerialNumber] {
		t.Fatalf("expected certificate %s to be returned when filtering by DigitalSignature", cert1.SerialNumber)
	}
	if !foundSerials[cert3.SerialNumber] {
		t.Fatalf("expected certificate %s to be returned when filtering by DigitalSignature", cert3.SerialNumber)
	}
	if foundSerials[cert2.SerialNumber] {
		t.Fatalf("did not expect certificate %s to be returned when filtering by DigitalSignature", cert2.SerialNumber)
	}
}

func TestGetCertificatesFilterByExtensionExtendedKeyUsageIgnoreCase(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running BeforeEach: %s", err)
	}

	ca := createActiveCA(t, caTest.HttpCASDK)

	cert1 := createCertificateWithExtensions(t, caTest.HttpCASDK, ca.ID, "eku-client-auth", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	cert2 := createCertificateWithExtensions(t, caTest.HttpCASDK, ca.ID, "eku-server-auth", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	cert3 := createCertificateWithExtensions(t, caTest.HttpCASDK, ca.ID, "eku-both", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning})

	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "extensions.extended_key_usage",
				Value:           "clientauth",
				FilterOperation: resources.StringArrayContainsIgnoreCase,
			},
		},
	}

	_, err = caTest.HttpCASDK.GetCertificates(context.Background(), services.GetCertificatesInput{
		ListInput: resources.ListInput[models.Certificate]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Certificate) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetCertificates returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 certificates filtered by extended key usage, got %d", len(found))
	}

	foundSerials := map[string]bool{}
	for _, cert := range found {
		foundSerials[cert.SerialNumber] = true
	}

	if !foundSerials[cert1.SerialNumber] {
		t.Fatalf("expected certificate %s to be returned when filtering by ClientAuth", cert1.SerialNumber)
	}
	if !foundSerials[cert3.SerialNumber] {
		t.Fatalf("expected certificate %s to be returned when filtering by ClientAuth", cert3.SerialNumber)
	}
	if foundSerials[cert2.SerialNumber] {
		t.Fatalf("did not expect certificate %s to be returned when filtering by ClientAuth", cert2.SerialNumber)
	}
}
