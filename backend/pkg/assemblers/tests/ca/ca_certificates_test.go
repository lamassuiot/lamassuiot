package ca

import (
	"context"
	"crypto/x509"
	"fmt"
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
func TestGetCertificatesFilterByMetadataJsonPath(t *testing.T) {
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

	// Create two certificates and add different metadata
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create first CA and certificate: %s", err)
	}

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create second CA and certificate: %s", err)
	}

	// Update metadata for cert1 with environment=production
	ud1 := make(map[string]interface{})
	ud1["environment"] = "production"
	ud1["region"] = "us-west-1"
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// Update metadata for cert2 with environment=staging
	ud2 := make(map[string]interface{})
	ud2["environment"] = "staging"
	ud2["region"] = "us-east-1"
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// Test 1: Query certificates using JSONPath to select by environment=production
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           "exists($.environment)",
				FilterOperation: resources.JsonPathExpression,
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

	// Should return both certificates since both have $.environment
	if len(found) != 2 {
		t.Fatalf("expected 2 certificates with $.environment path, got %d", len(found))
	}

	// Test 2: Query using JSONPath to select certificates in us-west-1 region
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.region)`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with $.region path, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathComplex(t *testing.T) {
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

	// Create certificates with complex nested metadata
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create first CA and certificate: %s", err)
	}

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create second CA and certificate: %s", err)
	}

	// Update cert1 with tags array containing production tag
	ud1 := make(map[string]interface{})
	tags1 := []map[string]interface{}{
		{"key": "production", "value": "true"},
		{"key": "critical", "value": "high"},
	}
	ud1["tags"] = tags1
	ud1["owner"] = map[string]interface{}{
		"team":    "platform",
		"contact": "platform@example.com",
	}

	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// Update cert2 with tags array containing staging tag
	ud2 := make(map[string]interface{})
	tags2 := []map[string]interface{}{
		{"key": "staging", "value": "true"},
		{"key": "critical", "value": "low"},
	}
	ud2["tags"] = tags2
	ud2["owner"] = map[string]interface{}{
		"team":    "development",
		"contact": "dev@example.com",
	}

	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// Test 1: Query using complex JSONPath expression to match tags with key 'production'
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.tags[*] ? (@.key == "production"))`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate filtered by tags[?(@.key=='production')], got %d", len(found))
	}

	if found[0].SerialNumber != cert1.SerialNumber {
		t.Fatalf("expected certificate serial %s, got %s", cert1.SerialNumber, found[0].SerialNumber)
	}

	// Test 2: Query using nested path to match owner team
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.owner.team)`,
				FilterOperation: resources.JsonPathExpression,
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

	// Both certificates have $.owner.team
	if len(found) != 2 {
		t.Fatalf("expected 2 certificates with $.owner.team path, got %d", len(found))
	}

	// Test 3: Query using array index to match first tag
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.tags[0].key)`,
				FilterOperation: resources.JsonPathExpression,
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

	// Both certificates have tags[0].key
	if len(found) != 2 {
		t.Fatalf("expected 2 certificates with $.tags[0].key path, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathNoMatch(t *testing.T) {
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

	// Create certificate with metadata
	_, cert, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create CA and certificate: %s", err)
	}

	// Update metadata
	ud := make(map[string]interface{})
	ud["environment"] = "production"
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert: %s", err)
	}

	// Query using JSONPath for non-existent field
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.nonexistent.field)`,
				FilterOperation: resources.JsonPathExpression,
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

	// Should return 0 certificates since the path doesn't exist
	if len(found) != 0 {
		t.Fatalf("expected 0 certificates for non-existent JSONPath, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathValueMatching(t *testing.T) {
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

	// Create three certificates with different metadata
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

	// Update metadata for cert1 - environment=production
	ud1 := make(map[string]interface{})
	ud1["environment"] = "production"
	ud1["version"] = 2
	ud1["critical"] = true
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// Update metadata for cert2 - environment=staging
	ud2 := make(map[string]interface{})
	ud2["environment"] = "staging"
	ud2["version"] = 1
	ud2["critical"] = false
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// Update metadata for cert3 - environment=development
	ud3 := make(map[string]interface{})
	ud3["environment"] = "development"
	ud3["version"] = 3
	ud3["critical"] = true
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert3.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert3: %s", err)
	}

	// Test 1: String equality - filter by environment == "production"
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment == "production"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with environment='production', got %d", len(found))
	}
	if found[0].SerialNumber != cert1.SerialNumber {
		t.Fatalf("expected cert1, got %s", found[0].SerialNumber)
	}

	// Test 2: String inequality - filter by environment != "production"
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment != "production"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with environment!='production', got %d", len(found))
	}

	// Test 3: Numeric comparison - version > 1
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.version > 1`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with version>1, got %d", len(found))
	}

	// Test 4: Numeric comparison - version <= 2
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.version <= 2`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with version<=2, got %d", len(found))
	}

	// Test 5: Boolean comparison - critical == true
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.critical == true`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with critical==true, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathLogicalOperators(t *testing.T) {
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

	// Create certificates with different metadata
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

	// cert1: production + critical
	ud1 := make(map[string]interface{})
	ud1["environment"] = "production"
	ud1["critical"] = true
	ud1["version"] = 2
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// cert2: production + not critical
	ud2 := make(map[string]interface{})
	ud2["environment"] = "production"
	ud2["critical"] = false
	ud2["version"] = 1
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// cert3: staging + critical
	ud3 := make(map[string]interface{})
	ud3["environment"] = "staging"
	ud3["critical"] = true
	ud3["version"] = 3
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert3.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert3: %s", err)
	}

	// Test 1: AND operator - production AND critical
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment == "production" && $.critical == true`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with production AND critical, got %d", len(found))
	}
	if found[0].SerialNumber != cert1.SerialNumber {
		t.Fatalf("expected cert1, got %s", found[0].SerialNumber)
	}

	// Test 2: OR operator - staging OR version > 2
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment == "staging" || $.version > 2`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with staging OR version>2, got %d", len(found))
	}

	// Test 3: NOT operator - critical equals false (explicit check)
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.critical == false`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with critical==false, got %d", len(found))
	}
	if found[0].SerialNumber != cert2.SerialNumber {
		t.Fatalf("expected cert2, got %s", found[0].SerialNumber)
	}

	// Test 4: Complex expression with parentheses - (production OR staging) AND critical
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `($.environment == "production" || $.environment == "staging") && $.critical == true`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with (production OR staging) AND critical, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathArrayOperations(t *testing.T) {
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

	// Create certificates with array metadata
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

	// cert1: tags with "production" and "web"
	ud1 := make(map[string]interface{})
	ud1["tags"] = []string{"production", "web", "frontend"}
	ud1["ports"] = []int{80, 443}
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// cert2: tags with "staging" and "api"
	ud2 := make(map[string]interface{})
	ud2["tags"] = []string{"staging", "api", "backend"}
	ud2["ports"] = []int{8080, 8443}
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// cert3: tags with "production" and "api"
	ud3 := make(map[string]interface{})
	ud3["tags"] = []string{"production", "api"}
	ud3["ports"] = []int{443, 8080}
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert3.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert3: %s", err)
	}

	// Test 1: Array contains specific string - tags contains "production"
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.tags[*] ? (@ == "production"))`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with 'production' tag, got %d", len(found))
	}

	// Test 2: Array index access - first tag is "staging"
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.tags[0] == "staging"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with tags[0]=='staging', got %d", len(found))
	}
	if found[0].SerialNumber != cert2.SerialNumber {
		t.Fatalf("expected cert2, got %s", found[0].SerialNumber)
	}

	// Test 3: Array with numeric comparison - ports contains value > 8000
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.ports[*] ? (@ > 8000))`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with ports > 8000, got %d", len(found))
	}

	// Test 4: Array last element access - last tag is "backend"
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.tags[last] == "backend"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with tags[last]=='backend', got %d", len(found))
	}

	// Test 5: Multiple array conditions - has "production" AND "api"
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.tags[*] ? (@ == "production")) && exists($.tags[*] ? (@ == "api"))`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with both 'production' and 'api' tags, got %d", len(found))
	}
	if found[0].SerialNumber != cert3.SerialNumber {
		t.Fatalf("expected cert3, got %s", found[0].SerialNumber)
	}
}

func TestGetCertificatesFilterByMetadataJsonPathStringOperations(t *testing.T) {
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

	// Create certificates with string metadata
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

	// cert1: hostname starts with "web"
	ud1 := make(map[string]interface{})
	ud1["hostname"] = "web-server-01.example.com"
	ud1["description"] = "Production Web Server"
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// cert2: hostname starts with "api"
	ud2 := make(map[string]interface{})
	ud2["hostname"] = "api-gateway-01.example.com"
	ud2["description"] = "API Gateway Instance"
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// cert3: hostname starts with "web"
	ud3 := make(map[string]interface{})
	ud3["hostname"] = "web-server-02.example.com"
	ud3["description"] = "Staging Environment"
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert3.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert3: %s", err)
	}

	// Test 1: starts_with operator - hostname starts with "web"
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.hostname starts with "web"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with hostname starting with 'web', got %d", len(found))
	}

	// Test 2: like_regex operator - hostname matches pattern
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.hostname like_regex "^api.*"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate matching regex '^api.*', got %d", len(found))
	}
	if found[0].SerialNumber != cert2.SerialNumber {
		t.Fatalf("expected cert2, got %s", found[0].SerialNumber)
	}

	// Test 3: like_regex with case insensitive flag - description contains "production"
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.description like_regex "PRODUCTION" flag "i"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with 'production' in description, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathTypeChecking(t *testing.T) {
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

	// Create certificates with different data types
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create first CA and certificate: %s", err)
	}

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create second CA and certificate: %s", err)
	}

	// cert1: mixed types
	ud1 := make(map[string]interface{})
	ud1["stringField"] = "test"
	ud1["numberField"] = 42
	ud1["boolField"] = true
	ud1["arrayField"] = []string{"a", "b"}
	ud1["objectField"] = map[string]string{"key": "value"}
	ud1["nullField"] = nil
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert1.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert1: %s", err)
	}

	// cert2: some types
	ud2 := make(map[string]interface{})
	ud2["stringField"] = "another"
	ud2["numberField"] = 100
	_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
		SerialNumber: cert2.SerialNumber,
		Patches: chelpers.NewPatchBuilder().
			Add(chelpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for cert2: %s", err)
	}

	// Test 1: type() function - check for number type
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.numberField.type() == "number"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with number type, got %d", len(found))
	}

	// Test 2: type() function - check for array type
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.arrayField.type() == "array"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with array type, got %d", len(found))
	}

	// Test 3: type() function - check for object type
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.objectField.type() == "object"`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with object type, got %d", len(found))
	}

	// Test 4: Check for null with exists
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `exists($.boolField)`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 1 certificate with boolField, got %d", len(found))
	}
}

func TestGetCertificatesFilterByMetadataJsonPathNumericRanges(t *testing.T) {
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

	// Create certificates with numeric metadata
	certs := []*models.Certificate{}
	for i := 1; i <= 5; i++ {
		_, cert, err := createCAAndCertificate(caTest.Service)
		if err != nil {
			t.Fatalf("failed to create certificate %d: %s", i, err)
		}
		certs = append(certs, cert)

		ud := make(map[string]interface{})
		ud["score"] = i * 20 // 20, 40, 60, 80, 100
		ud["priority"] = float64(i) * 1.5
		_, err = caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
			SerialNumber: cert.SerialNumber,
			Patches: chelpers.NewPatchBuilder().
				Add(chelpers.JSONPointerBuilder(), ud).
				Build(),
		})
		if err != nil {
			t.Fatalf("failed to update metadata for cert %d: %s", i, err)
		}
	}

	// Test 1: Greater than - score > 50
	found := []*models.Certificate{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.score > 50`,
				FilterOperation: resources.JsonPathExpression,
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

	if len(found) != 3 {
		t.Fatalf("expected 3 certificates with score>50, got %d", len(found))
	}

	// Test 2: Less than or equal - score <= 60
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.score <= 60`,
				FilterOperation: resources.JsonPathExpression,
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

	if len(found) != 3 {
		t.Fatalf("expected 3 certificates with score<=60, got %d", len(found))
	}

	// Test 3: Range - score between 40 and 80
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.score >= 40 && $.score <= 80`,
				FilterOperation: resources.JsonPathExpression,
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

	if len(found) != 3 {
		t.Fatalf("expected 3 certificates with 40<=score<=80, got %d", len(found))
	}

	// Test 4: Float comparison - priority > 4.5
	found = []*models.Certificate{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.priority > 4.5`,
				FilterOperation: resources.JsonPathExpression,
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
		t.Fatalf("expected 2 certificates with priority>4.5, got %d", len(found))
	}
}
