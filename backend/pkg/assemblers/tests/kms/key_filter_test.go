package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestGetKeysFilterByMetadataJsonPath(t *testing.T) {
	ctx := context.Background()
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	// Create keys with different metadata
	ecdsaKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key1, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{
		Name:       "key-1",
		PrivateKey: ecdsaKey1,
		Metadata:   map[string]any{},
		Tags:       []string{"prod"},
		EngineID:   "filesystem-1",
	})
	if err != nil {
		t.Fatalf("failed to import key1: %s", err)
	}

	ecdsaKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{
		Name:       "key-2",
		PrivateKey: ecdsaKey2,
		Metadata:   map[string]any{},
		Tags:       []string{"dev"},
		EngineID:   "filesystem-1",
	})
	if err != nil {
		t.Fatalf("failed to import key2: %s", err)
	}

	ecdsaKey3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key3, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{
		Name:       "key-3",
		PrivateKey: ecdsaKey3,
		Metadata:   map[string]any{},
		Tags:       []string{"test"},
		EngineID:   "filesystem-1",
	})
	if err != nil {
		t.Fatalf("failed to import key3: %s", err)
	}

	// Update metadata for each key
	ud1 := make(map[string]interface{})
	ud1["environment"] = "production"
	ud1["purpose"] = "signing"
	ud1["critical"] = true
	ud1["rotation_days"] = 90
	_, err = kmsTest.Service.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
		ID: key1.KeyID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for key1: %s", err)
	}

	ud2 := make(map[string]interface{})
	ud2["environment"] = "development"
	ud2["purpose"] = "encryption"
	ud2["critical"] = false
	ud2["rotation_days"] = 30
	_, err = kmsTest.Service.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
		ID: key2.KeyID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for key2: %s", err)
	}

	ud3 := make(map[string]interface{})
	ud3["environment"] = "staging"
	ud3["purpose"] = "signing"
	ud3["critical"] = true
	ud3["rotation_days"] = 60
	_, err = kmsTest.Service.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
		ID: key3.KeyID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for key3: %s", err)
	}

	// Test 1: Simple equality - environment equals "production"
	found := []*models.Key{}
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

	_, err = kmsTest.HttpKMSSDK.GetKeys(ctx, services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Key) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetKeys returned error: %s", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 key with environment=production, got %d", len(found))
	}
	if found[0].KeyID != key1.KeyID {
		t.Fatalf("expected key1, got %s", found[0].KeyID)
	}

	// Test 2: Boolean matching - critical equals true
	found = []*models.Key{}
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

	_, err = kmsTest.HttpKMSSDK.GetKeys(ctx, services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Key) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetKeys returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 keys with critical=true, got %d", len(found))
	}

	// Test 3: AND operator - purpose equals "signing" AND critical equals true
	found = []*models.Key{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.purpose == "signing" && $.critical == true`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = kmsTest.HttpKMSSDK.GetKeys(ctx, services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Key) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetKeys returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 keys with signing AND critical, got %d", len(found))
	}

	// Test 4: OR operator - environment equals "production" OR environment equals "staging"
	found = []*models.Key{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment == "production" || $.environment == "staging"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = kmsTest.HttpKMSSDK.GetKeys(ctx, services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Key) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetKeys returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 keys with production OR staging, got %d", len(found))
	}

	// Test 5: Numeric comparison - rotation_days greater than 30
	found = []*models.Key{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.rotation_days > 30`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = kmsTest.HttpKMSSDK.GetKeys(ctx, services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Key) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetKeys returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 keys with rotation_days > 30, got %d", len(found))
	}

	// Test 6: String matching with starts with
	found = []*models.Key{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.purpose starts with "sign"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = kmsTest.HttpKMSSDK.GetKeys(ctx, services.GetKeysInput{
		ListInput: resources.ListInput[models.Key]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Key) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetKeys returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 keys with purpose starting with sign, got %d", len(found))
	}
}
