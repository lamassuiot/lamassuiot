package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// createActiveCA creates a fresh CA and reuses an existing issuance profile if
// provided, otherwise creates a new one.  It returns the ready-to-sign CA.
func createActiveCA(t *testing.T, caSDK services.CAService) *models.CACertificate {
	t.Helper()
	issuanceDur := models.TimeDuration(time.Hour * 12)
	caDur := models.TimeDuration(time.Hour * 24)

	profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		t.Fatalf("createActiveCA: could not create issuance profile: %s", err)
	}

	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "CreateCertTest-CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("createActiveCA: could not create CA: %s", err)
	}
	return ca
}

// revokeCA moves the CA to Revoked status so we can test inactive-CA scenarios.
func revokeCA(t *testing.T, caSDK services.CAService, caID string) {
	t.Helper()
	_, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
		CAID:             caID,
		Status:           models.StatusRevoked,
		RevocationReason: models.RevocationReason(1),
	})
	if err != nil {
		t.Fatalf("revokeCA: could not revoke CA %s: %s", caID, err)
	}
}

// ---------------------------------------------------------------------------
// TestCreateCertificateSDK – exercises the full HTTP stack:
//   controller → service backend → event-publisher middleware → audit middleware
// ---------------------------------------------------------------------------

func TestCreateCertificateSDK(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create test server: %s", err)
	}

	caTest := serverTest.CA
	kmsTest := serverTest.KMS

	var testcases = []struct {
		name        string
		before      func(caSDK services.CAService) (caID string, err error)
		run         func(caSDK services.CAService, caID string) (*models.Certificate, error)
		resultCheck func(cert *models.Certificate, err error) error
	}{
		// ------------------------------------------------------------------ //
		// Success: generate-mode (new RSA key)
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-RSA",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "rsa-generate-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				if cert.Subject.CommonName != "rsa-generate-cert" {
					return fmt.Errorf("expected CN 'rsa-generate-cert', got '%s'", cert.Subject.CommonName)
				}
				if cert.Certificate.PublicKeyAlgorithm != x509.RSA {
					return fmt.Errorf("expected RSA public key algorithm, got %v", cert.Certificate.PublicKeyAlgorithm)
				}
				if cert.Status != models.StatusActive {
					return fmt.Errorf("expected StatusActive, got %s", cert.Status)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: generate-mode (new ECDSA key)
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-ECDSA",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.ECDSA),
						Bits: 256,
					},
					Subject: models.Subject{CommonName: "ecdsa-generate-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				if cert.Certificate.PublicKeyAlgorithm != x509.ECDSA {
					return fmt.Errorf("expected ECDSA public key algorithm, got %v", cert.Certificate.PublicKeyAlgorithm)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: reuse-mode (pre-existing KMS key referenced by KeyID)
		// ------------------------------------------------------------------ //
		{
			name: "OK/ReuseKeyMode-ExistingKey",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				// Create a standalone key in KMS that the certificate should reuse.
				key, err := kmsTest.HttpKMSSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Algorithm: "RSA",
					Size:      2048,
					Name:      "reuse-key-for-cert",
				})
				if err != nil {
					return nil, fmt.Errorf("failed to pre-create KMS key: %s", err)
				}

				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						KeyIdentifier: key.KeyID,
					},
					Subject: models.Subject{CommonName: "reuse-key-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate with reused key but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				if cert.Subject.CommonName != "reuse-key-cert" {
					return fmt.Errorf("expected CN 'reuse-key-cert', got '%s'", cert.Subject.CommonName)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: inline issuance profile overrides CA default
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-WithInlineIssuanceProfile",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				customValidity := models.TimeDuration(time.Hour * 6)
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "inline-profile-cert"},
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        models.Validity{Type: models.Duration, Duration: customValidity},
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				// Validate that the 6h validity from the inline profile was applied.
				actualDuration := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
				expectedDuration := time.Hour * 6
				if actualDuration != expectedDuration {
					return fmt.Errorf("expected certificate validity %s, got %s", expectedDuration, actualDuration)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: referenced issuance profile
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-WithIssuanceProfileID",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				customValidity := models.TimeDuration(time.Hour * 3)
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:     "custom-3h-profile",
						Validity: models.Validity{Type: models.Duration, Duration: customValidity},
					},
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create issuance profile: %s", err)
				}

				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject:           models.Subject{CommonName: "profile-id-cert"},
					IssuanceProfileID: profile.ID,
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				actualDuration := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
				expectedDuration := time.Hour * 3
				if actualDuration != expectedDuration {
					return fmt.Errorf("expected certificate validity %s from profile, got %s", expectedDuration, actualDuration)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: generate-mode certificate is MANAGED (KMS key bound to cert)
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-ManagedType",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "managed-type-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				if cert.Type != models.CertificateTypeManaged {
					return fmt.Errorf("expected CertificateTypeManaged, got %s", cert.Type)
				}
				if cert.EngineID == "" {
					return fmt.Errorf("expected non-empty EngineID on MANAGED certificate")
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: explicit EngineID routes key generation to the named engine
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-WithExplicitEngineID",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				// "filesystem-1" is the default engine wired by PrepareCryptoEnginesForTest.
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type:     models.KeyType(x509.RSA),
						Bits:     2048,
						EngineID: "filesystem-1",
					},
					Subject: models.Subject{CommonName: "explicit-engine-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				if cert.Type != models.CertificateTypeManaged {
					return fmt.Errorf("expected CertificateTypeManaged, got %s", cert.Type)
				}
				if cert.EngineID != "filesystem-1" {
					return fmt.Errorf("expected EngineID 'filesystem-1', got '%s'", cert.EngineID)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: metadata is preserved on the issued certificate
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-WithMetadata",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "meta-cert"},
					Metadata: map[string]any{
						"device-id": "device-123",
						"env":       "test",
					},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert.Metadata["device-id"] != "device-123" {
					return fmt.Errorf("expected metadata device-id='device-123', got '%v'", cert.Metadata["device-id"])
				}
				if cert.Metadata["env"] != "test" {
					return fmt.Errorf("expected metadata env='test', got '%v'", cert.Metadata["env"])
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: both generate and reuse modes set simultaneously
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InvalidKeySpec-BothModes",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						// Both generate and reuse mode set simultaneously.
						Type:          models.KeyType(x509.RSA),
						Bits:          2048,
						KeyIdentifier: "some-existing-key-id",
					},
					Subject: models.Subject{CommonName: "both-modes-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrInvalidKeySpec but got no error")
				}
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: neither generate nor reuse mode set
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InvalidKeySpec-NeitherMode",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID:    caID,
					KeySpec: services.CertificateKeySpec{
						// Nothing set - no Type/Bits and no KeyIdentifier.
					},
					Subject: models.Subject{CommonName: "neither-mode-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrInvalidKeySpec but got no error")
				}
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: generate-mode with Type set but Bits==0
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InvalidKeySpec-TypeWithoutBits",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						// Bits intentionally omitted (0).
					},
					Subject: models.Subject{CommonName: "no-bits-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrInvalidKeySpec but got no error")
				}
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: generate-mode with Bits set but Type==0 (other partial direction)
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InvalidKeySpec-BitsWithoutType",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						// Type intentionally omitted (zero value); only Bits set.
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "no-type-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrInvalidKeySpec but got no error")
				}
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: CA does not exist
		// ------------------------------------------------------------------ //
		{
			name: "ERR/CANotFound",
			before: func(caSDK services.CAService) (string, error) {
				return "non-existent-ca-id", nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "ca-not-found-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrCANotFound but got no error")
				}
				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("expected ErrCANotFound but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: CA exists but is revoked (inactive)
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InactiveCA-Revoked",
			before: func(caSDK services.CAService) (string, error) {
				ca := createActiveCA(t, caSDK)
				revokeCA(t, caSDK, ca.ID)
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "revoked-ca-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrCAStatus but got no error")
				}
				if !errors.Is(err, errs.ErrCAStatus) {
					return fmt.Errorf("expected ErrCAStatus but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: reuse-mode but the referenced key does not exist
		// ------------------------------------------------------------------ //
		{
			name: "ERR/KeyNotFound-ReuseMode",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						KeyIdentifier: "this-key-does-not-exist",
					},
					Subject: models.Subject{CommonName: "missing-key-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got an error for a missing key but got no error")
				}
				// The service wraps the KMS error; ErrKeyNotFound is expected.
				if !errors.Is(err, errs.ErrKeyNotFound) {
					return fmt.Errorf("expected ErrKeyNotFound but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Error: referenced issuance profile does not exist
		// ------------------------------------------------------------------ //
		{
			name: "ERR/IssuanceProfileNotFound-ByID",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject:           models.Subject{CommonName: "bad-profile-cert"},
					IssuanceProfileID: "non-existent-profile-id",
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should have got ErrIssuanceProfileNotFound but got no error")
				}
				if !errors.Is(err, errs.ErrIssuanceProfileNotFound) {
					return fmt.Errorf("expected ErrIssuanceProfileNotFound but got: %s", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Success: when both IssuanceProfileID and IssuanceProfile are set, the
		// inline profile wins (documents precedence via HTTP stack end-to-end)
		// ------------------------------------------------------------------ //
		{
			name: "OK/BothProfilesSet-InlineWins",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				// Referenced profile: 8h validity.
				refProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:     "8h-profile",
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(8 * time.Hour)},
					},
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create issuance profile: %s", err)
				}

				// Inline profile: 4h validity — must win over the 8h reference.
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject:           models.Subject{CommonName: "both-profiles-cert"},
					IssuanceProfileID: refProfile.ID,
					IssuanceProfile: &models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(4 * time.Hour)},
					},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should have created certificate but got error: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				actualDuration := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
				if actualDuration != 4*time.Hour {
					return fmt.Errorf("expected 4h validity from inline profile, got %s", actualDuration)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("BeforeEach failed: %s", err)
			}

			caID, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("before failed: %s", err)
			}

			cert, runErr := tc.run(caTest.HttpCASDK, caID)
			if err := tc.resultCheck(cert, runErr); err != nil {
				t.Fatalf("unexpected result: %s", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCreateCertificateService – exercises service-layer logic directly
// (bypasses HTTP / event-publisher middleware, so it tests core business rules)
// ---------------------------------------------------------------------------

func TestCreateCertificateService(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(caSDK services.CAService) (caID string, err error)
		run         func(caSDK services.CAService, caID string) (*models.Certificate, error)
		resultCheck func(cert *models.Certificate, err error) error
	}{
		// ------------------------------------------------------------------ //
		// Service validates key-spec before touching DB
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InvalidKeySpec-NeitherMode",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID:    caID,
					KeySpec: services.CertificateKeySpec{},
					Subject: models.Subject{CommonName: "bad-spec"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec, got: %v", err)
				}
				return nil
			},
		},
		{
			name: "ERR/InvalidKeySpec-BothModes",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type:          models.KeyType(x509.RSA),
						Bits:          2048,
						KeyIdentifier: "some-key",
					},
					Subject: models.Subject{CommonName: "both-modes"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec, got: %v", err)
				}
				return nil
			},
		},
		{
			name: "ERR/InvalidKeySpec-TypeWithoutBits",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						// Bits = 0, invalid generate-mode
					},
					Subject: models.Subject{CommonName: "type-no-bits"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec, got: %v", err)
				}
				return nil
			},
		},
		{
			name: "ERR/InvalidKeySpec-BitsWithoutType",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						// Type = zero value, Bits set — other partial direction
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "bits-no-type"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if !errors.Is(err, errs.ErrInvalidKeySpec) {
					return fmt.Errorf("expected ErrInvalidKeySpec, got: %v", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Service returns ErrCANotFound for a missing CA
		// ------------------------------------------------------------------ //
		{
			name: "ERR/CANotFound",
			before: func(caSDK services.CAService) (string, error) {
				return "does-not-exist", nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "missing-ca-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("expected ErrCANotFound, got: %v", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Service rejects an expired CA (ErrCAStatus)
		// ------------------------------------------------------------------ //
		{
			name: "ERR/InactiveCA-Expired",
			before: func(caSDK services.CAService) (string, error) {
				ca := createActiveCA(t, caSDK)
				// Manually force the CA to the Expired status.
				_, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:   ca.ID,
					Status: models.StatusExpired,
				})
				if err != nil {
					return "", fmt.Errorf("could not expire CA: %s", err)
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "expired-ca-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if !errors.Is(err, errs.ErrCAStatus) {
					return fmt.Errorf("expected ErrCAStatus for expired CA, got: %v", err)
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Service falls back to CA's default profile when none is specified
		// ------------------------------------------------------------------ //
		{
			name: "OK/FallbackToCADefaultProfile",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				// No IssuanceProfile / IssuanceProfileID provided →
				// the service should use the CA's own ProfileID.
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "fallback-profile-cert"},
					// IssuanceProfileID deliberately omitted.
					// IssuanceProfile deliberately omitted.
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("expected success with CA default profile, got: %s", err)
				}
				if cert == nil {
					return fmt.Errorf("returned certificate is nil")
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Service marks generate-mode certificates as MANAGED (KMS binding)
		// ------------------------------------------------------------------ //
		{
			name: "OK/GenerateMode-ManagedType",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject: models.Subject{CommonName: "managed-type-cert"},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("expected success, got: %s", err)
				}
				if cert.Type != models.CertificateTypeManaged {
					return fmt.Errorf("expected CertificateTypeManaged, got %s", cert.Type)
				}
				if cert.EngineID == "" {
					return fmt.Errorf("expected non-empty EngineID on MANAGED certificate")
				}
				return nil
			},
		},
		// ------------------------------------------------------------------ //
		// Service inlines profile takes precedence over a profile ID
		// ------------------------------------------------------------------ //
		{
			name: "OK/InlineProfileOverridesProfileID",
			before: func(caSDK services.CAService) (string, error) {
				return createActiveCA(t, caSDK).ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.Certificate, error) {
				// Create a referenced profile with a 9h validity.
				refProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:     "9h-profile",
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(9 * time.Hour)},
					},
				})
				if err != nil {
					return nil, fmt.Errorf("failed creating profile: %s", err)
				}

				// Provide both an inline profile (5h) AND the ID reference (9h).
				// Inline must win.
				return caSDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
					CAID: caID,
					KeySpec: services.CertificateKeySpec{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
					Subject:           models.Subject{CommonName: "priority-cert"},
					IssuanceProfileID: refProfile.ID,
					IssuanceProfile: &models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(5 * time.Hour)},
					},
				})
			},
			resultCheck: func(cert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("expected success, got: %s", err)
				}
				actualDuration := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
				if actualDuration != 5*time.Hour {
					return fmt.Errorf("expected 5h validity from inline profile, got %s", actualDuration)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := serverTest.BeforeEach(); err != nil {
				t.Fatalf("BeforeEach failed: %s", err)
			}

			caID, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("before failed: %s", err)
			}

			cert, runErr := tc.run(caTest.Service, caID)
			if err := tc.resultCheck(cert, runErr); err != nil {
				t.Fatalf("unexpected result: %s", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCreateCertificateEventAndAuditBehavior
//
// Tests that the event-publisher and audit middlewares do not suppress or
// modify the certificate returned by CreateCertificate, and that the issued
// certificate is persisted in the storage backend and can be retrieved.
//
// Even without a live event bus the event-publisher middleware is still wired
// in the HTTP test server; a successful call exercises the entire middleware
// chain (CAEventPublisher.CreateCertificate → CAAuditEventPublisher.CreateCertificate
// → CAServiceBackend.CreateCertificate).  The test verifies:
//   1. The middleware chain returns the certificate transparently.
//   2. The certificate is stored (GetCertificateBySerialNumber succeeds).
//   3. A failed call (inactive CA) also flows through the middleware chain
//      without modifying the error.
// ---------------------------------------------------------------------------

func TestCreateCertificateEventAndAuditBehavior(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create test server: %s", err)
	}

	caTest := serverTest.CA

	// ------------------------------------------------------------------ //
	// Success path: middleware chain returns certificate; it is persisted.
	// ------------------------------------------------------------------ //
	t.Run("OK/MiddlewareChain-CertificatePersisted", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("BeforeEach failed: %s", err)
		}

		ca := createActiveCA(t, caTest.Service)

		// Call through the full HTTP SDK (includes event-publisher + audit middlewares).
		cert, err := caTest.HttpCASDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
			CAID: ca.ID,
			KeySpec: services.CertificateKeySpec{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			Subject: models.Subject{CommonName: "event-audit-cert"},
		})
		if err != nil {
			t.Fatalf("CreateCertificate via SDK returned unexpected error: %s", err)
		}
		if cert == nil {
			t.Fatalf("CreateCertificate returned nil certificate")
		}

		// The middleware chain must preserve the serial number in the returned
		// object so the event subject ("certificate/<sn>") is well-formed.
		if cert.SerialNumber == "" {
			t.Fatalf("SerialNumber is empty – event publisher subject would be malformed")
		}

		// Verify the certificate was actually stored (proves the service
		// ran to completion despite the middleware wrappers).
		stored, err := caTest.Service.GetCertificateBySerialNumber(context.Background(),
			services.GetCertificatesBySerialNumberInput{SerialNumber: cert.SerialNumber})
		if err != nil {
			t.Fatalf("GetCertificateBySerialNumber returned error after CreateCertificate: %s", err)
		}
		if stored.SerialNumber != cert.SerialNumber {
			t.Fatalf("stored serial %s differs from returned serial %s", stored.SerialNumber, cert.SerialNumber)
		}
		if stored.Subject.CommonName != "event-audit-cert" {
			t.Fatalf("stored CN '%s' differs from issued CN 'event-audit-cert'", stored.Subject.CommonName)
		}
	})

	// ------------------------------------------------------------------ //
	// Error path: middleware chain propagates ErrCAStatus without swallowing.
	// ------------------------------------------------------------------ //
	t.Run("ERR/MiddlewareChain-ErrorPropagated", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("BeforeEach failed: %s", err)
		}

		ca := createActiveCA(t, caTest.Service)
		revokeCA(t, caTest.Service, ca.ID)

		_, err := caTest.HttpCASDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
			CAID: ca.ID,
			KeySpec: services.CertificateKeySpec{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			Subject: models.Subject{CommonName: "should-fail"},
		})
		if err == nil {
			t.Fatalf("expected error from middleware chain, got nil")
		}
		if !errors.Is(err, errs.ErrCAStatus) {
			t.Fatalf("expected ErrCAStatus through middleware chain, got: %s", err)
		}
	})

	// ------------------------------------------------------------------ //
	// Multiple sequential calls: each certificate gets a unique serial number
	// (proves KMS key creation and signing round-trip is repeatable).
	// ------------------------------------------------------------------ //
	t.Run("OK/SequentialCalls-UniqueSerialNumbers", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("BeforeEach failed: %s", err)
		}

		ca := createActiveCA(t, caTest.Service)
		serials := map[string]struct{}{}

		for i := 0; i < 3; i++ {
			cert, err := caTest.HttpCASDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
				CAID: ca.ID,
				KeySpec: services.CertificateKeySpec{
					Type: models.KeyType(x509.RSA),
					Bits: 2048,
				},
				Subject: models.Subject{CommonName: fmt.Sprintf("seq-cert-%d", i)},
			})
			if err != nil {
				t.Fatalf("iteration %d: CreateCertificate returned error: %s", i, err)
			}
			if _, exists := serials[cert.SerialNumber]; exists {
				t.Fatalf("duplicate serial number detected: %s", cert.SerialNumber)
			}
			serials[cert.SerialNumber] = struct{}{}
		}
	})

	// ------------------------------------------------------------------ //
	// Reuse key: the same KMS key can back multiple certificates.
	// ------------------------------------------------------------------ //
	t.Run("OK/ReuseKey-MultipleCerts", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("BeforeEach failed: %s", err)
		}

		ca := createActiveCA(t, caTest.Service)
		kmsTest := serverTest.KMS

		sharedKey, err := kmsTest.HttpKMSSDK.CreateKey(context.Background(), services.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "shared-key",
		})
		if err != nil {
			t.Fatalf("could not create shared KMS key: %s", err)
		}

		var prevSerial string
		for i := 0; i < 2; i++ {
			cert, err := caTest.HttpCASDK.CreateCertificate(context.Background(), services.CreateCertificateInput{
				CAID: ca.ID,
				KeySpec: services.CertificateKeySpec{
					KeyIdentifier: sharedKey.KeyID,
				},
				Subject: models.Subject{CommonName: fmt.Sprintf("shared-key-cert-%d", i)},
			})
			if err != nil {
				t.Fatalf("iteration %d: CreateCertificate (reuse key) returned error: %s", i, err)
			}
			if cert.SerialNumber == prevSerial {
				t.Fatalf("expected unique serial for each certificate, got duplicate: %s", cert.SerialNumber)
			}
			prevSerial = cert.SerialNumber
		}
	})
}
