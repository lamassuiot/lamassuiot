package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
	"uuid"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

// TestGetStatsFiltered tests filtered statistics for CAs and Certificates
func TestGetStatsFiltered(t *testing.T) {
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
	createCAWithMetadata := func(t *testing.T, id, commonName string, metadata map[string]any) *models.CACertificate {
		profile := createProfile(t)
		ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
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
				createCAWithMetadata(t, uuid.NewV7().String(), "CA2", map[string]any{"env": "production"})
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
	}

	for _, tc := range testcases {

		t.Run(tc.name, func(t *testing.T) {
			err := serverTest.BeforeEach()
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

// TestGetCertificatesStats covers GET /v1/certificates/stats, which replaced the
// certificate block of GET /v1/stats so certificate counts run under the certificate
// list filter instead of the CA one.
func TestGetCertificatesStats(t *testing.T) {
	signCertificate := func(t *testing.T, caID string, metadata map[string]any) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed generating key: %s", err)
		}
		csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test-cert"}, key)
		if err != nil {
			t.Fatalf("failed generating CSR: %s", err)
		}
		cert, err := serverTest.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID: caID, CertRequest: (*models.X509CertificateRequest)(csr),
		})
		if err != nil {
			t.Fatalf("failed signing certificate: %s", err)
		}
		_, err = serverTest.CA.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
			SerialNumber: cert.SerialNumber,
			Patches:      chelpers.NewPatchBuilder().Add(chelpers.JSONPointerBuilder(), metadata).Build(),
		})
		if err != nil {
			t.Fatalf("failed updating certificate metadata: %s", err)
		}
	}
	metadataFilter := func(field string, op resources.FilterOperation, value string) *resources.QueryParameters {
		return &resources.QueryParameters{Filters: []resources.FilterOption{{Field: field, FilterOperation: op, Value: value}}}
	}

	for _, tc := range []struct {
		name   string
		params *resources.QueryParameters
		check  func(t *testing.T, stats *models.CertificatesStats, err error)
	}{
		{
			name: "OK/WithoutFilters",
			check: func(t *testing.T, stats *models.CertificatesStats, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				// The CA certificate plus the three issued ones.
				if stats.TotalCertificates != 4 {
					t.Fatalf("expected 4 certificates, got %d", stats.TotalCertificates)
				}
			},
		},
		{
			name:   "OK/FilterByMetadata",
			params: metadataFilter("metadata", resources.JsonPathExpression, `$.type == "server"`),
			check: func(t *testing.T, stats *models.CertificatesStats, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if stats.TotalCertificates != 2 {
					t.Fatalf("expected 2 server certificates, got %d", stats.TotalCertificates)
				}
				if stats.CertificateStatus[models.StatusActive] != 2 {
					t.Fatalf("expected 2 active server certificates, got %d", stats.CertificateStatus[models.StatusActive])
				}
			},
		},
		{
			name:   "Err/StatusFilterRejected",
			params: metadataFilter("status", resources.EnumEqual, string(models.StatusActive)),
			check: func(t *testing.T, _ *models.CertificatesStats, err error) {
				if err == nil {
					t.Fatalf("should've rejected status filter, but got no error")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}
			ca, err := initCA(serverTest.CA.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}
			signCertificate(t, ca.ID, map[string]any{"type": "server"})
			signCertificate(t, ca.ID, map[string]any{"type": "client"})
			signCertificate(t, ca.ID, map[string]any{"type": "server"})

			stats, err := serverTest.CA.HttpCASDK.GetCertificatesStats(context.Background(), services.GetCertificatesStatsInput{QueryParameters: tc.params})
			tc.check(t, stats, err)
		})
	}
}

// TestGetStatsByCAIDFiltered tests filtered statistics for certificates within a CA
func TestGetStatsByCAIDFiltered(t *testing.T) {
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("BeforeEach failed: %s", err)
	}

	caTest := serverTest.CA

	// Helper function to sign a certificate with metadata
	signCertificateWithMetadata := func(t *testing.T, caID string, metadata map[string]any) *models.Certificate {
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
				signCertificateWithMetadata(t, ca.ID, map[string]any{"type": "server"})
				signCertificateWithMetadata(t, ca.ID, map[string]any{"type": "client"})
				signCertificateWithMetadata(t, ca.ID, map[string]any{"type": "server"})
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

		t.Run(tc.name, func(t *testing.T) {
			err := serverTest.BeforeEach()
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
