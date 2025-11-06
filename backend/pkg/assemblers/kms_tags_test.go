package assemblers

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestUpdateKeyTags(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) (*models.Key, error)
		run         func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error)
		resultCheck func(updatedKey *models.Key, err error) error
	}{
		{
			name: "OK/AddTagsToNewKey",
			before: func(svc services.KMSService) (*models.Key, error) {
				return svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key for Tags",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "filesystem-1",
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"production", "critical", "us-east-1"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 3 {
					return fmt.Errorf("expected 3 tags, got %d", len(updatedKey.Tags))
				}
				expectedTags := map[string]bool{
					"production": false,
					"critical":   false,
					"us-east-1":  false,
				}
				for _, tag := range updatedKey.Tags {
					if _, exists := expectedTags[tag]; exists {
						expectedTags[tag] = true
					} else {
						return fmt.Errorf("unexpected tag: %s", tag)
					}
				}
				for tag, found := range expectedTags {
					if !found {
						return fmt.Errorf("expected tag '%s' not found", tag)
					}
				}
				return nil
			},
		},
		{
			name: "OK/UpdateExistingTags",
			before: func(svc services.KMSService) (*models.Key, error) {
				key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Initial Tags",
					Algorithm: "ECDSA",
					Size:      256,
					EngineID:  "filesystem-1",
				})
				if err != nil {
					return nil, err
				}
				// Add initial tags
				return svc.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"development", "temporary"},
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"production", "permanent", "critical"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 3 {
					return fmt.Errorf("expected 3 tags after update, got %d", len(updatedKey.Tags))
				}
				// Check old tags are replaced
				for _, tag := range updatedKey.Tags {
					if tag == "development" || tag == "temporary" {
						return fmt.Errorf("old tag '%s' should have been replaced", tag)
					}
				}
				// Check new tags exist
				expectedTags := map[string]bool{
					"production": false,
					"permanent":  false,
					"critical":   false,
				}
				for _, tag := range updatedKey.Tags {
					if _, exists := expectedTags[tag]; exists {
						expectedTags[tag] = true
					}
				}
				for tag, found := range expectedTags {
					if !found {
						return fmt.Errorf("expected tag '%s' not found", tag)
					}
				}
				return nil
			},
		},
		{
			name: "OK/ClearAllTags",
			before: func(svc services.KMSService) (*models.Key, error) {
				key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Tags to Clear",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "filesystem-1",
				})
				if err != nil {
					return nil, err
				}
				// Add initial tags
				return svc.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"tag1", "tag2", "tag3"},
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 0 {
					return fmt.Errorf("expected 0 tags after clearing, got %d", len(updatedKey.Tags))
				}
				return nil
			},
		},
		{
			name: "OK/SetSingleTag",
			before: func(svc services.KMSService) (*models.Key, error) {
				return svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key Single Tag",
					Algorithm: "ECDSA",
					Size:      384,
					EngineID:  "filesystem-1",
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"important"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 1 {
					return fmt.Errorf("expected 1 tag, got %d", len(updatedKey.Tags))
				}
				if updatedKey.Tags[0] != "important" {
					return fmt.Errorf("expected tag 'important', got '%s'", updatedKey.Tags[0])
				}
				return nil
			},
		},
		{
			name: "OK/UpdateTagsMultipleTimes",
			before: func(svc services.KMSService) (*models.Key, error) {
				key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key Multiple Updates",
					Algorithm: "RSA",
					Size:      4096,
					EngineID:  "filesystem-1",
				})
				if err != nil {
					return nil, err
				}
				// First update
				key, err = svc.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"tag1"},
				})
				if err != nil {
					return nil, err
				}
				// Second update
				return svc.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"tag1", "tag2"},
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"final-tag"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 1 {
					return fmt.Errorf("expected 1 tag after final update, got %d", len(updatedKey.Tags))
				}
				if updatedKey.Tags[0] != "final-tag" {
					return fmt.Errorf("expected tag 'final-tag', got '%s'", updatedKey.Tags[0])
				}
				return nil
			},
		},
		{
			name: "OK/UpdateTagsUsingAlias",
			before: func(svc services.KMSService) (*models.Key, error) {
				key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Alias",
					Algorithm: "ECDSA",
					Size:      256,
					EngineID:  "filesystem-1",
				})
				if err != nil {
					return nil, err
				}
				// Add an alias
				return svc.UpdateKeyAliases(context.Background(), services.UpdateKeyAliasesInput{
					ID:      key.KeyID,
					Patches: []models.PatchOperation{{Op: models.PatchAdd, Path: "/-", Value: "my-test-alias"}},
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				// Update tags using the alias instead of KeyID
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   "my-test-alias",
					Tags: []string{"aliased-tag"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 1 {
					return fmt.Errorf("expected 1 tag, got %d", len(updatedKey.Tags))
				}
				if updatedKey.Tags[0] != "aliased-tag" {
					return fmt.Errorf("expected tag 'aliased-tag', got '%s'", updatedKey.Tags[0])
				}
				return nil
			},
		},
		{
			name: "OK/UpdateTagsUsingPKCS11URI",
			before: func(svc services.KMSService) (*models.Key, error) {
				return svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with PKCS11 URI",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "filesystem-1",
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				// Update tags using PKCS11URI
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.PKCS11URI,
					Tags: []string{"uri-based-tag"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(updatedKey.Tags) != 1 {
					return fmt.Errorf("expected 1 tag, got %d", len(updatedKey.Tags))
				}
				if updatedKey.Tags[0] != "uri-based-tag" {
					return fmt.Errorf("expected tag 'uri-based-tag', got '%s'", updatedKey.Tags[0])
				}
				return nil
			},
		},
		{
			name: "Error/KeyNotFound",
			before: func(svc services.KMSService) (*models.Key, error) {
				return &models.Key{KeyID: "nonexistent-key-id"}, nil
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   "nonexistent-key-id",
					Tags: []string{"tag1"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected error for nonexistent key, got nil")
				}
				return nil
			},
		},
		{
			name: "Error/EmptyKeyID",
			before: func(svc services.KMSService) (*models.Key, error) {
				return &models.Key{}, nil
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   "",
					Tags: []string{"tag1"},
				})
			},
			resultCheck: func(updatedKey *models.Key, err error) error {
				if err == nil {
					return fmt.Errorf("expected validation error for empty key ID, got nil")
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

			key, err := tc.before(kmsTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			updatedKey, err := tc.run(kmsTest.HttpKMSSDK, key)
			err = tc.resultCheck(updatedKey, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetKeyWithTags(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) (*models.Key, error)
		run         func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error)
		resultCheck func(retrievedKey *models.Key, err error) error
	}{
		{
			name: "OK/GetKeyWithTags",
			before: func(svc services.KMSService) (*models.Key, error) {
				key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key with Tags for Retrieval",
					Algorithm: "ECDSA",
					Size:      256,
					EngineID:  "filesystem-1",
				})
				if err != nil {
					return nil, err
				}
				// Add tags
				return svc.UpdateKeyTags(context.Background(), services.UpdateKeyTagsInput{
					ID:   key.KeyID,
					Tags: []string{"test-tag-1", "test-tag-2", "test-tag-3"},
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.GetKey(context.Background(), services.GetKeyInput{
					Identifier: key.KeyID,
				})
			},
			resultCheck: func(retrievedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if len(retrievedKey.Tags) != 3 {
					return fmt.Errorf("expected 3 tags, got %d", len(retrievedKey.Tags))
				}
				expectedTags := map[string]bool{
					"test-tag-1": false,
					"test-tag-2": false,
					"test-tag-3": false,
				}
				for _, tag := range retrievedKey.Tags {
					if _, exists := expectedTags[tag]; exists {
						expectedTags[tag] = true
					}
				}
				for tag, found := range expectedTags {
					if !found {
						return fmt.Errorf("expected tag '%s' not found in retrieved key", tag)
					}
				}
				return nil
			},
		},
		{
			name: "OK/GetKeyWithNoTags",
			before: func(svc services.KMSService) (*models.Key, error) {
				return svc.CreateKey(context.Background(), services.CreateKeyInput{
					Name:      "Test Key without Tags",
					Algorithm: "RSA",
					Size:      2048,
					EngineID:  "filesystem-1",
				})
			},
			run: func(kmsSDK services.KMSService, key *models.Key) (*models.Key, error) {
				return kmsSDK.GetKey(context.Background(), services.GetKeyInput{
					Identifier: key.KeyID,
				})
			},
			resultCheck: func(retrievedKey *models.Key, err error) error {
				if err != nil {
					return fmt.Errorf("should not get error, but got: %s", err)
				}
				if retrievedKey.Tags == nil {
					return fmt.Errorf("expected empty tags array, got nil")
				}
				if len(retrievedKey.Tags) != 0 {
					return fmt.Errorf("expected 0 tags, got %d", len(retrievedKey.Tags))
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

			key, err := tc.before(kmsTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			retrievedKey, err := tc.run(kmsTest.HttpKMSSDK, key)
			err = tc.resultCheck(retrievedKey, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
