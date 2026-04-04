package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

// TestRegisterExistingKey tests basic functionality
// Note: In real usage, RegisterExistingKey is for keys that exist in the engine
// but not in KMS database. However, since our test setup automatically registers
// keys when we create/import them, we test the validation and error cases.
func TestRegisterExistingKey(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) (string, error)
		run         func(kmsSDK services.KMSService, keyID string) (*models.Key, error)
		resultCheck func(keyID string, registeredKey *models.Key, err error) error
	}{
		{
			name: "Err/RegisterAlreadyExistingKey",
			before: func(svc services.KMSService) (string, error) {
				// Create a key normally - it will be in both engine and KMS
				key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Already Registered Key",
					Algorithm: "RSA",
					Size:      2048,
				})
				if err != nil {
					return "", err
				}
				return key.KeyID, nil
			},
			run: func(kmsSDK services.KMSService, keyID string) (*models.Key, error) {
				// Try to register a key that's already registered
				return kmsSDK.RegisterExistingKey(context.Background(), services.RegisterExistingKeyInput{
					KeyID:    keyID,
					Name:     "Duplicate Registration",
					Tags:     []string{"test"},
					Metadata: map[string]any{},
				})
			},
			resultCheck: func(keyID string, registeredKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("should have errored for already registered key, but got none")
				}

				if registeredKey != nil {
					return fmt.Errorf("registered key should be nil on error")
				}

				return nil
			},
		},
		{
			name: "Err/RegisterNonExistentKey",
			before: func(svc services.KMSService) (string, error) {
				// Return a fake key ID that doesn't exist in the engine
				return "non-existent-key-id-12345", nil
			},
			run: func(kmsSDK services.KMSService, keyID string) (*models.Key, error) {
				return kmsSDK.RegisterExistingKey(context.Background(), services.RegisterExistingKeyInput{
					KeyID:    keyID,
					Name:     "Should Fail",
					Tags:     []string{},
					Metadata: map[string]any{},
				})
			},
			resultCheck: func(keyID string, registeredKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("should have errored for non-existent key, but got none")
				}

				if registeredKey != nil {
					return fmt.Errorf("registered key should be nil on error")
				}

				return nil
			},
		},
		{
			name: "OK/ValidationCheck",
			before: func(svc services.KMSService) (string, error) {
				// Test that the function properly validates keys exist in the engine
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return "", err
				}

				// Generate key ID from public key (similar to how crypto engines do it)
				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
				if err != nil {
					return "", err
				}
				hash := sha256.Sum256(pubKeyBytes)
				keyID := hex.EncodeToString(hash[:])

				return keyID, nil
			},
			run: func(kmsSDK services.KMSService, keyID string) (*models.Key, error) {
				// Try to register - should fail because key doesn't exist in engine
				return kmsSDK.RegisterExistingKey(context.Background(), services.RegisterExistingKeyInput{
					KeyID:    keyID,
					Name:     "Test Key",
					Tags:     []string{},
					Metadata: map[string]any{},
				})
			},
			resultCheck: func(keyID string, registeredKey *models.Key, err error) error {
				// Should error because the key doesn't actually exist in the crypto engine
				if err == nil {
					return fmt.Errorf("should have errored for key not in engine")
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := kmsTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			keyID, err := tc.before(kmsTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			registeredKey, err := tc.run(kmsTest.HttpKMSSDK, keyID)
			if err := tc.resultCheck(keyID, registeredKey, err); err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
