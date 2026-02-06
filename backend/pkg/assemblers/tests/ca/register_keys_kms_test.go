package ca

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestRegisterExistingCAKeysInKMS(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.
		WithDatabase("ca", "kms").
		WithService(tests.CA, tests.KMS).
		Build(t)
	if err != nil {
		t.Fatalf("could not create test server: %s", err)
	}

	caService := serverTest.CA.Service
	kmsService := serverTest.KMS.Service

	// Helper function to create an issuance profile (required for CA creation)
	createProfile := func(t *testing.T) *models.IssuanceProfile {
		issuanceDur := models.TimeDuration(time.Hour * 24 * 365) // 1 year
		profile, err := caService.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{
				Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
			},
		})
		if err != nil {
			t.Fatalf("failed creating issuance profile: %s", err)
		}
		return profile
	}

	var testcases = []struct {
		name        string
		before      func(t *testing.T) (*models.CACertificate, error)
		run         func(ca *models.CACertificate) (*models.Key, error)
		resultCheck func(ca *models.CACertificate, key *models.Key, err error) error
	}{
		{
			name: "Err/AlreadyExists",
			before: func(t *testing.T) (*models.CACertificate, error) {
				profile := createProfile(t)
				caDuration := models.TimeDuration(time.Hour * 24 * 365)

				// Create CA - key will be automatically registered in KMS
				ca, err := caService.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Already Registered CA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDuration},
					ProfileID:    profile.ID,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create CA: %w", err)
				}

				// Verify key exists in KMS
				_, err = kmsService.GetKey(context.Background(), services.GetKeyInput{
					Identifier: ca.Certificate.SubjectKeyID,
				})
				if err != nil {
					return nil, fmt.Errorf("key should exist in KMS after CA creation: %w", err)
				}

				return ca, nil
			},
			run: func(ca *models.CACertificate) (*models.Key, error) {
				// Try to register a key that's already in KMS
				return kmsService.RegisterExistingKey(context.Background(), services.RegisterExistingKeyInput{
					KeyID: ca.Certificate.SubjectKeyID,
					Name:  ca.Certificate.Subject.CommonName,
				})
			},
			resultCheck: func(ca *models.CACertificate, key *models.Key, err error) error {
				// Should get an error that key already exists
				if err == nil {
					return fmt.Errorf("expected error when registering already existing key")
				}

				// Verify key still exists in KMS unchanged
				existingKey, err := kmsService.GetKey(context.Background(), services.GetKeyInput{
					Identifier: ca.Certificate.SubjectKeyID,
				})
				if err != nil {
					return fmt.Errorf("key should still exist in KMS: %w", err)
				}

				if existingKey.KeyID != ca.Certificate.SubjectKeyID {
					return fmt.Errorf("key ID should be unchanged")
				}

				return nil
			},
		},
		{
			name: "Err/NonExistentKey",
			before: func(t *testing.T) (*models.CACertificate, error) {
				profile := createProfile(t)
				caDuration := models.TimeDuration(time.Hour * 24 * 365)

				// Create a CA to get a valid engine ID
				ca, err := caService.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Test CA for Engine ID"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDuration},
					ProfileID:    profile.ID,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create CA: %w", err)
				}

				return ca, nil
			},
			run: func(ca *models.CACertificate) (*models.Key, error) {
				// Try to register a non-existent key ID
				fakeKeyID := hex.EncodeToString([]byte("nonexistent-key-id-for-testing"))
				name := "nonexistent-key-id-for-testing"
				return kmsService.RegisterExistingKey(context.Background(), services.RegisterExistingKeyInput{
					KeyID: fakeKeyID,
					Name:  name,
				})
			},
			resultCheck: func(ca *models.CACertificate, key *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error when registering non-existent key")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := tc.before(t)
			if err != nil {
				t.Fatalf("before failed: %s", err)
			}

			key, runErr := tc.run(ca)

			if err := tc.resultCheck(ca, key, runErr); err != nil {
				t.Fatalf("result check failed: %s", err)
			}
		})
	}
}
