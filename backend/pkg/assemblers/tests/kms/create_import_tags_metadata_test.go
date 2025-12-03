package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestCreateKeyWithTagsAndMetadata(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) error
		run         func(kmsSDK services.KMSService) (*models.Key, error)
		resultCheck func(createdKey *models.Key, err error) error
	}{
		{
			name:   "OK/CreateKeyWithTags",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Tags",
					Algorithm: "RSA",
					Size:      2048,
					Tags:      []string{"production", "critical", "backup-enabled"},
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if createdKey == nil {
					return fmt.Errorf("created key should not be nil")
				}

				if len(createdKey.Tags) != 3 {
					return fmt.Errorf("expected 3 tags, got %d", len(createdKey.Tags))
				}

				expectedTags := []string{"production", "critical", "backup-enabled"}
				for _, tag := range expectedTags {
					found := false
					for _, keyTag := range createdKey.Tags {
						if keyTag == tag {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("expected tag '%s' not found in key tags", tag)
					}
				}

				return nil
			},
		},
		{
			name:   "OK/CreateKeyWithMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Metadata",
					Algorithm: "ECDSA",
					Size:      256,
					Metadata: map[string]any{
						"owner":       "security-team",
						"project":     "api-gateway",
						"environment": "production",
						"cost-center": 1234,
					},
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if createdKey == nil {
					return fmt.Errorf("created key should not be nil")
				}

				if len(createdKey.Metadata) != 4 {
					return fmt.Errorf("expected 4 metadata entries, got %d", len(createdKey.Metadata))
				}

				if createdKey.Metadata["owner"] != "security-team" {
					return fmt.Errorf("expected owner='security-team', got %v", createdKey.Metadata["owner"])
				}

				if createdKey.Metadata["project"] != "api-gateway" {
					return fmt.Errorf("expected project='api-gateway', got %v", createdKey.Metadata["project"])
				}

				if createdKey.Metadata["environment"] != "production" {
					return fmt.Errorf("expected environment='production', got %v", createdKey.Metadata["environment"])
				}

				// JSON unmarshaling converts numbers to float64
				costCenter, ok := createdKey.Metadata["cost-center"].(float64)
				if !ok {
					return fmt.Errorf("cost-center should be a number")
				}
				if costCenter != 1234 {
					return fmt.Errorf("expected cost-center=1234, got %v", costCenter)
				}

				return nil
			},
		},
		{
			name:   "OK/CreateKeyWithTagsAndMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Both",
					Algorithm: "RSA",
					Size:      4096,
					Tags:      []string{"development", "testing"},
					Metadata: map[string]any{
						"purpose":    "testing",
						"created-by": "automated-tests",
					},
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if createdKey == nil {
					return fmt.Errorf("created key should not be nil")
				}

				if len(createdKey.Tags) != 2 {
					return fmt.Errorf("expected 2 tags, got %d", len(createdKey.Tags))
				}

				if len(createdKey.Metadata) != 2 {
					return fmt.Errorf("expected 2 metadata entries, got %d", len(createdKey.Metadata))
				}

				return nil
			},
		},
		{
			name:   "OK/CreateKeyWithoutTagsOrMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key Plain",
					Algorithm: "ECDSA",
					Size:      384,
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if createdKey == nil {
					return fmt.Errorf("created key should not be nil")
				}

				// Should have empty arrays/maps, not nil
				if createdKey.Tags == nil {
					return fmt.Errorf("tags should be empty array, not nil")
				}

				if len(createdKey.Tags) != 0 {
					return fmt.Errorf("expected 0 tags, got %d", len(createdKey.Tags))
				}

				if createdKey.Metadata == nil {
					return fmt.Errorf("metadata should be empty map, not nil")
				}

				if len(createdKey.Metadata) != 0 {
					return fmt.Errorf("expected 0 metadata entries, got %d", len(createdKey.Metadata))
				}

				return nil
			},
		},
		{
			name:   "OK/CreateKeyWithEmptyTagsAndMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				return kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key Empty Arrays",
					Algorithm: "RSA",
					Size:      2048,
					Tags:      []string{},
					Metadata:  map[string]any{},
				})
			},
			resultCheck: func(createdKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if createdKey == nil {
					return fmt.Errorf("created key should not be nil")
				}

				if len(createdKey.Tags) != 0 {
					return fmt.Errorf("expected 0 tags, got %d", len(createdKey.Tags))
				}

				if len(createdKey.Metadata) != 0 {
					return fmt.Errorf("expected 0 metadata entries, got %d", len(createdKey.Metadata))
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err = kmsTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.before(kmsTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(kmsTest.HttpKMSSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestImportKeyWithTagsAndMetadata(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) error
		run         func(kmsSDK services.KMSService) (*models.Key, error)
		resultCheck func(importedKey *models.Key, err error) error
	}{
		{
			name:   "OK/ImportRSAKeyWithTags",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}

				return kmsSDK.ImportKey(context.Background(), services.ImportKeyInput{
					PrivateKey: privKey,
					Name:       "Imported RSA Key with Tags",
					Tags:       []string{"imported", "rsa-key", "archive"},
				})
			},
			resultCheck: func(importedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if importedKey == nil {
					return fmt.Errorf("imported key should not be nil")
				}

				if len(importedKey.Tags) != 3 {
					return fmt.Errorf("expected 3 tags, got %d", len(importedKey.Tags))
				}

				expectedTags := []string{"imported", "rsa-key", "archive"}
				for _, tag := range expectedTags {
					found := false
					for _, keyTag := range importedKey.Tags {
						if keyTag == tag {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("expected tag '%s' not found in key tags", tag)
					}
				}

				if importedKey.Algorithm != "RSA" {
					return fmt.Errorf("expected algorithm RSA, got %s", importedKey.Algorithm)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportECDSAKeyWithMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}

				return kmsSDK.ImportKey(context.Background(), services.ImportKeyInput{
					PrivateKey: privKey,
					Name:       "Imported ECDSA Key with Metadata",
					Metadata: map[string]any{
						"import-source": "legacy-system",
						"migration-id":  "MIG-2024-001",
						"validated":     true,
					},
				})
			},
			resultCheck: func(importedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if importedKey == nil {
					return fmt.Errorf("imported key should not be nil")
				}

				if len(importedKey.Metadata) != 3 {
					return fmt.Errorf("expected 3 metadata entries, got %d", len(importedKey.Metadata))
				}

				if importedKey.Metadata["import-source"] != "legacy-system" {
					return fmt.Errorf("expected import-source='legacy-system', got %v", importedKey.Metadata["import-source"])
				}

				if importedKey.Metadata["migration-id"] != "MIG-2024-001" {
					return fmt.Errorf("expected migration-id='MIG-2024-001', got %v", importedKey.Metadata["migration-id"])
				}

				if importedKey.Algorithm != "ECDSA" {
					return fmt.Errorf("expected algorithm ECDSA, got %s", importedKey.Algorithm)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportKeyWithTagsAndMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}

				return kmsSDK.ImportKey(context.Background(), services.ImportKeyInput{
					PrivateKey: privKey,
					Name:       "Imported Key with Both",
					Tags:       []string{"migration", "legacy"},
					Metadata: map[string]any{
						"original-id":   "OLD-KEY-123",
						"migrated-date": "2024-11-06",
					},
				})
			},
			resultCheck: func(importedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if importedKey == nil {
					return fmt.Errorf("imported key should not be nil")
				}

				if len(importedKey.Tags) != 2 {
					return fmt.Errorf("expected 2 tags, got %d", len(importedKey.Tags))
				}

				if len(importedKey.Metadata) != 2 {
					return fmt.Errorf("expected 2 metadata entries, got %d", len(importedKey.Metadata))
				}

				return nil
			},
		},
		{
			name:   "OK/ImportKeyWithoutTagsOrMetadata",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (*models.Key, error) {
				privKey, err := rsa.GenerateKey(rand.Reader, 4096)
				if err != nil {
					return nil, err
				}

				return kmsSDK.ImportKey(context.Background(), services.ImportKeyInput{
					PrivateKey: privKey,
					Name:       "Imported Plain Key",
				})
			},
			resultCheck: func(importedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if importedKey == nil {
					return fmt.Errorf("imported key should not be nil")
				}

				// Should have empty arrays/maps, not nil
				if importedKey.Tags == nil {
					return fmt.Errorf("tags should be empty array, not nil")
				}

				if len(importedKey.Tags) != 0 {
					return fmt.Errorf("expected 0 tags, got %d", len(importedKey.Tags))
				}

				if importedKey.Metadata == nil {
					return fmt.Errorf("metadata should be empty map, not nil")
				}

				if len(importedKey.Metadata) != 0 {
					return fmt.Errorf("expected 0 metadata entries, got %d", len(importedKey.Metadata))
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err = kmsTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.before(kmsTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(kmsTest.HttpKMSSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestCreateAndRetrieveKeyWithTagsAndMetadata(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		run         func(kmsSDK services.KMSService) error
		resultCheck func(err error) error
	}{
		{
			name: "OK/CreateRetrieveKeyPersistsTags",
			run: func(kmsSDK services.KMSService) error {
				// Create key with tags
				createdKey, err := kmsSDK.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Persistence Test Key",
					Algorithm: "RSA",
					Size:      2048,
					Tags:      []string{"persistent", "test"},
					Metadata: map[string]any{
						"test-run": "persistence-check",
					},
				})
				if err != nil {
					return fmt.Errorf("failed to create key: %s", err)
				}

				// Retrieve the key
				retrievedKey, err := kmsSDK.GetKey(context.Background(), services.GetKeyInput{
					Identifier: createdKey.KeyID,
				})
				if err != nil {
					return fmt.Errorf("failed to retrieve key: %s", err)
				}

				// Verify tags persisted
				if len(retrievedKey.Tags) != 2 {
					return fmt.Errorf("expected 2 tags after retrieval, got %d", len(retrievedKey.Tags))
				}

				// Verify metadata persisted
				if len(retrievedKey.Metadata) != 1 {
					return fmt.Errorf("expected 1 metadata entry after retrieval, got %d", len(retrievedKey.Metadata))
				}

				if retrievedKey.Metadata["test-run"] != "persistence-check" {
					return fmt.Errorf("metadata value not persisted correctly")
				}

				return nil
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err = kmsTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(kmsTest.HttpKMSSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
