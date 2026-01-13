package dmsmanager

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestGetDMSFilterByMetadataJsonPath(t *testing.T) {
	ctx := context.Background()
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	// Create DMSs with different metadata
	dms1, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       "dms-1",
		Name:     "Production Fleet",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dms1: %s", err)
	}

	dms2, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       "dms-2",
		Name:     "Development Fleet",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dms2: %s", err)
	}

	dms3, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       "dms-3",
		Name:     "Staging Fleet",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dms3: %s", err)
	}

	// Update metadata for each DMS
	ud1 := make(map[string]interface{})
	ud1["environment"] = "production"
	ud1["region"] = "us-east-1"
	ud1["critical"] = true
	ud1["device_count"] = 1000
	_, err = dmsMgr.Service.UpdateDMSMetadata(ctx, services.UpdateDMSMetadataInput{
		ID: dms1.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for dms1: %s", err)
	}

	ud2 := make(map[string]interface{})
	ud2["environment"] = "development"
	ud2["region"] = "us-west-2"
	ud2["critical"] = false
	ud2["device_count"] = 50
	_, err = dmsMgr.Service.UpdateDMSMetadata(ctx, services.UpdateDMSMetadataInput{
		ID: dms2.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for dms2: %s", err)
	}

	ud3 := make(map[string]interface{})
	ud3["environment"] = "staging"
	ud3["region"] = "us-east-1"
	ud3["critical"] = true
	ud3["device_count"] = 200
	_, err = dmsMgr.Service.UpdateDMSMetadata(ctx, services.UpdateDMSMetadataInput{
		ID: dms3.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for dms3: %s", err)
	}

	// Test 1: Simple equality - environment equals "production"
	found := []*models.DMS{}
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

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 DMS with environment=production, got %d", len(found))
	}
	if found[0].ID != dms1.ID {
		t.Fatalf("expected dms1, got %s", found[0].ID)
	}

	// Test 2: Boolean matching - critical equals true
	found = []*models.DMS{}
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

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with critical=true, got %d", len(found))
	}

	// Test 3: AND operator - region equals "us-east-1" AND critical equals true
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.region == "us-east-1" && $.critical == true`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with us-east-1 AND critical, got %d", len(found))
	}

	// Test 4: OR operator - environment equals "production" OR environment equals "staging"
	found = []*models.DMS{}
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

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with production OR staging, got %d", len(found))
	}

	// Test 5: Numeric comparison - device_count greater than 100
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.device_count > 100`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with device_count > 100, got %d", len(found))
	}

	// Test 6: String matching with starts with
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.region starts with "us-"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 3 {
		t.Fatalf("expected 3 DMS with region starting with us-, got %d", len(found))
	}
}

func TestGetDMSFilterBySettingsJsonPath(t *testing.T) {
	ctx := context.Background()
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	// Create DMSs with different settings configurations
	dms1, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       "dms-settings-1",
		Name:     "Auto Enrollment Fleet",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol:          models.EST,
				EnableReplaceableEnrollment: true,
				RegistrationMode:            models.JITP,
				VerifyCSRSignature:          true,
			},
			ServerKeyGen: models.ServerKeyGenSettings{
				Enabled: true,
				Key: models.ServerKeyGenKey{
					Type: models.KeyType(1),
					Bits: 2048,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dms1: %s", err)
	}

	_, err = dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       "dms-settings-2",
		Name:     "Manual Enrollment Fleet",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol:          models.EST,
				EnableReplaceableEnrollment: false,
				RegistrationMode:            models.PreRegistration,
				VerifyCSRSignature:          false,
			},
			ServerKeyGen: models.ServerKeyGenSettings{
				Enabled: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dms2: %s", err)
	}

	_, err = dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       "dms-settings-3",
		Name:     "High Security Fleet",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol:          models.EST,
				EnableReplaceableEnrollment: false,
				RegistrationMode:            models.JITP,
				VerifyCSRSignature:          true,
			},
			ServerKeyGen: models.ServerKeyGenSettings{
				Enabled: true,
				Key: models.ServerKeyGenKey{
					Type: models.KeyType(3),
					Bits: 256,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dms3: %s", err)
	}

	// Test 1: Filter by server_keygen_settings.enabled equals true
	found := []*models.DMS{}
	qp := &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "settings",
				Value:           `$.server_keygen_settings.enabled == true`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with server_keygen enabled, got %d", len(found))
	}

	// Test 2: Filter by enrollment_settings.registration_mode equals "JITP"
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "settings",
				Value:           `$.enrollment_settings.registration_mode == "JITP"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with JITP registration mode, got %d", len(found))
	}

	// Test 3: Filter by enrollment_settings.verify_csr_signature equals true
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "settings",
				Value:           `$.enrollment_settings.verify_csr_signature == true`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with verify_csr_signature enabled, got %d", len(found))
	}

	// Test 4: AND operator - server_keygen enabled AND verify_csr_signature enabled
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "settings",
				Value:           `$.server_keygen_settings.enabled == true && $.enrollment_settings.verify_csr_signature == true`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 DMS with server_keygen AND verify_csr_signature enabled, got %d", len(found))
	}

	// Test 5: Filter by server_keygen_settings.key.type equals "RSA"
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "settings",
				Value:           `$.server_keygen_settings.key.type == "RSA"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 DMS with RSA key type, got %d", len(found))
	}
	if found[0].ID != dms1.ID {
		t.Fatalf("expected dms1, got %s", found[0].ID)
	}

	// Test 6: Numeric comparison - server_keygen_settings.key.bits greater than or equal to 2048
	found = []*models.DMS{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "settings",
				Value:           `$.server_keygen_settings.key.bits >= 2048`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmsMgr.HttpDeviceManagerSDK.GetAll(ctx, services.GetAllInput{
		ListInput: resources.ListInput[models.DMS]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.DMS) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetAll returned error: %s", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 DMS with key bits >= 2048, got %d", len(found))
	}
}
