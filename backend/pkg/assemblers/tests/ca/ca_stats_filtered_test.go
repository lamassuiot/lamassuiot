package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

// TestGetStatsFiltered tests filtered statistics for CAs and Certificates
func TestGetStatsFiltered(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Helper function to create issuance profile
	createProfile := func(t *testing.T) *models.IssuanceProfile {
		profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{
				Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
			},
		})
		if err != nil {
			t.Fatalf("failed creating issuance profile: %s", err)
		}
		return profile
	}

	// Helper function to create CA with specific metadata
	createCAWithMetadata := func(t *testing.T, id, commonName string, metadata map[string]interface{}) *models.CACertificate {
		profile := createProfile(t)
		ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
			ID:           id,
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: commonName},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24 * 365)},
			ProfileID:    profile.ID,
			Metadata:     metadata,
		})
		if err != nil {
			t.Fatalf("failed creating CA: %s", err)
		}
		return ca
	}

	// Helper function to sign a certificate
	signCertificateWithMetadata := func(t *testing.T, caID string, metadata map[string]interface{}) *models.Certificate {
		// Generate key for CSR
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed generating key: %s", err)
		}

		// Generate CSR
		csr, err := chelpers.GenerateCertificateRequest(
			models.Subject{CommonName: "test-cert"},
			key,
		)
		if err != nil {
			t.Fatalf("failed generating CSR: %s", err)
		}

		cert, err := serverTest.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID:        caID,
			CertRequest: (*models.X509CertificateRequest)(csr),
		})
		if err != nil {
			t.Fatalf("failed signing certificate: %s", err)
		}

		// Update metadata after issuance if needed
		if metadata != nil {
			cert, err = serverTest.CA.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
				SerialNumber: cert.SerialNumber,
				Patches: chelpers.NewPatchBuilder().
					Add(chelpers.JSONPointerBuilder(), metadata).
					Build(),
			})
			if err != nil {
				t.Fatalf("failed updating certificate metadata: %s", err)
			}
		}

		return cert
	}

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CAStats, error)
		resultCheck func(*models.CAStats, error) error
	}{
		{
			name:   "OK/GetStatsWithoutFilters",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				return caSDK.GetStats(context.Background(), services.GetStatsInput{})
			},
			resultCheck: func(stats *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should've got stats without error, but got error: %s", err)
				}
				// Should have 1 CA from initCA
				if stats.CACertificatesStats.TotalCAs != 1 {
					return fmt.Errorf("expected 1 CA, got %d", stats.CACertificatesStats.TotalCAs)
				}
				return nil
			},
		},
		{
			name: "OK/FilterCAsByEngineID",
			before: func(svc services.CAService) error {
				// Create an additional CA with the default engine (filesystem-1)
				createCAWithMetadata(t, "ca-2", "CA2", map[string]interface{}{"env": "production"})
				return nil
			},
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				return caSDK.GetStats(context.Background(), services.GetStatsInput{
					CAQueryParameters: &resources.QueryParameters{
						Filters: []resources.FilterOption{
							{
								Field:           "engine_id",
								FilterOperation: resources.StringEqual,
								Value:           "filesystem-1",
							},
						},
					},
				})
			},
			resultCheck: func(stats *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should've got stats without error, but got error: %s", err)
				}
				// Both CAs should be in filesystem-1 engine
				if stats.CACertificatesStats.TotalCAs != 2 {
					return fmt.Errorf("expected 2 CAs, got %d", stats.CACertificatesStats.TotalCAs)
				}
				return nil
			},
		},
		{
			name: "OK/FilterCertificatesByMetadata",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return err
				}
				// Sign certificates with different metadata
				signCertificateWithMetadata(t, ca.ID, map[string]interface{}{"type": "server"})
				signCertificateWithMetadata(t, ca.ID, map[string]interface{}{"type": "client"})
				signCertificateWithMetadata(t, ca.ID, map[string]interface{}{"type": "server"})
				return nil
			},
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				return caSDK.GetStats(context.Background(), services.GetStatsInput{
					CertificateQueryParameters: &resources.QueryParameters{
						Filters: []resources.FilterOption{
							{
								Field:           "metadata",
								FilterOperation: resources.JsonPathExpression,
								Value:           "$.type == \"server\"",
							},
						},
					},
				})
			},
			resultCheck: func(stats *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should've got stats without error, but got error: %s", err)
				}
				// Should only count server certificates
				if stats.CertificatesStats.TotalCertificates != 2 {
					return fmt.Errorf("expected 2 server certificates, got %d", stats.CertificatesStats.TotalCertificates)
				}
				// CA stats should remain unfiltered (1 CA from initCA)
				if stats.CACertificatesStats.TotalCAs != 1 {
					return fmt.Errorf("expected 1 CA, got %d", stats.CACertificatesStats.TotalCAs)
				}
				return nil
			},
		},
		{
			name:   "Err/StatusFilterRejectedForCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				return caSDK.GetStats(context.Background(), services.GetStatsInput{
					CAQueryParameters: &resources.QueryParameters{
						Filters: []resources.FilterOption{
							{
								Field:           "status",
								FilterOperation: resources.EnumEqual,
								Value:           string(models.StatusActive),
							},
						},
					},
				})
			},
			resultCheck: func(stats *models.CAStats, err error) error {
				if err == nil {
					return fmt.Errorf("should've rejected status filter, but got no error")
				}
				return nil
			},
		},
		{
			name:   "Err/StatusFilterRejectedForCertificate",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				return caSDK.GetStats(context.Background(), services.GetStatsInput{
					CertificateQueryParameters: &resources.QueryParameters{
						Filters: []resources.FilterOption{
							{
								Field:           "status",
								FilterOperation: resources.EnumEqual,
								Value:           string(models.StatusActive),
							},
						},
					},
				})
			},
			resultCheck: func(stats *models.CAStats, err error) error {
				if err == nil {
					return fmt.Errorf("should've rejected status filter, but got no error")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

// TestGetStatsByCAIDFiltered tests filtered statistics for certificates within a CA
func TestGetStatsByCAIDFiltered(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Helper function to sign a certificate with metadata
	signCertificateWithMetadata := func(t *testing.T, caID string, metadata map[string]interface{}) *models.Certificate {
		// Generate key for CSR
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed generating key: %s", err)
		}

		// Generate CSR
		csr, err := chelpers.GenerateCertificateRequest(
			models.Subject{CommonName: "test-cert"},
			key,
		)
		if err != nil {
			t.Fatalf("failed generating CSR: %s", err)
		}

		cert, err := serverTest.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID:        caID,
			CertRequest: (*models.X509CertificateRequest)(csr),
		})
		if err != nil {
			t.Fatalf("failed signing certificate: %s", err)
		}

		// Update metadata after issuance if needed
		if metadata != nil {
			cert, err = serverTest.CA.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
				SerialNumber: cert.SerialNumber,
				Patches: chelpers.NewPatchBuilder().
					Add(chelpers.JSONPointerBuilder(), metadata).
					Build(),
			})
			if err != nil {
				t.Fatalf("failed updating certificate metadata: %s", err)
			}
		}

		return cert
	}

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (map[models.CertificateStatus]int, error)
		resultCheck func(map[models.CertificateStatus]int, error) error
	}{
		{
			name:   "OK/GetStatsByCAIDWithoutFilters",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (map[models.CertificateStatus]int, error) {
				return caSDK.GetStatsByCAID(context.Background(), services.GetStatsByCAIDInput{
					CAID: DefaultCAID,
				})
			},
			resultCheck: func(stats map[models.CertificateStatus]int, err error) error {
				if err != nil {
					return fmt.Errorf("should've got stats without error, but got error: %s", err)
				}
				// Should have status distribution
				if len(stats) == 0 {
					return fmt.Errorf("expected status distribution, but got empty map")
				}
				return nil
			},
		},
		{
			name: "OK/FilterCertificatesByMetadata",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return err
				}
				// Sign certificates with different metadata
				signCertificateWithMetadata(t, ca.ID, map[string]interface{}{"type": "server"})
				signCertificateWithMetadata(t, ca.ID, map[string]interface{}{"type": "client"})
				signCertificateWithMetadata(t, ca.ID, map[string]interface{}{"type": "server"})
				return nil
			},
			run: func(caSDK services.CAService) (map[models.CertificateStatus]int, error) {
				return caSDK.GetStatsByCAID(context.Background(), services.GetStatsByCAIDInput{
					CAID: DefaultCAID,
					CertificateQueryParameters: &resources.QueryParameters{
						Filters: []resources.FilterOption{
							{
								Field:           "metadata",
								FilterOperation: resources.JsonPathExpression,
								Value:           "$.type == \"server\"",
							},
						},
					},
				})
			},
			resultCheck: func(stats map[models.CertificateStatus]int, err error) error {
				if err != nil {
					return fmt.Errorf("should've got stats without error, but got error: %s", err)
				}
				// All server certificates should be active
				activeCount, exists := stats[models.StatusActive]
				if !exists {
					return fmt.Errorf("expected active status in distribution")
				}
				if activeCount != 2 {
					return fmt.Errorf("expected 2 active server certificates, got %d", activeCount)
				}
				return nil
			},
		},
		{
			name:   "Err/StatusFilterRejected",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (map[models.CertificateStatus]int, error) {
				return caSDK.GetStatsByCAID(context.Background(), services.GetStatsByCAIDInput{
					CAID: DefaultCAID,
					CertificateQueryParameters: &resources.QueryParameters{
						Filters: []resources.FilterOption{
							{
								Field:           "status",
								FilterOperation: resources.EnumEqual,
								Value:           string(models.StatusActive),
							},
						},
					},
				})
			},
			resultCheck: func(stats map[models.CertificateStatus]int, err error) error {
				if err == nil {
					return fmt.Errorf("should've rejected status filter, but got no error")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
