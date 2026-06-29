package devicemanager

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestGetDevicesFilterByMetadataJsonPath(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Create devices with different metadata
	dev1, err := dmgr.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        "device-1",
		Alias:     "Production Device",
		Tags:      []string{"prod"},
		Metadata:  map[string]interface{}{},
		DMSID:     "test-dms",
		Icon:      "device",
		IconColor: "#FF0000",
	})
	if err != nil {
		t.Fatalf("failed to create device1: %s", err)
	}

	dev2, err := dmgr.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        "device-2",
		Alias:     "Development Device",
		Tags:      []string{"dev"},
		Metadata:  map[string]interface{}{},
		DMSID:     "test-dms",
		Icon:      "device",
		IconColor: "#00FF00",
	})
	if err != nil {
		t.Fatalf("failed to create device2: %s", err)
	}

	dev3, err := dmgr.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        "device-3",
		Alias:     "Test Device",
		Tags:      []string{"test"},
		Metadata:  map[string]interface{}{},
		DMSID:     "test-dms",
		Icon:      "device",
		IconColor: "#0000FF",
	})
	if err != nil {
		t.Fatalf("failed to create device3: %s", err)
	}

	// Update metadata for each device
	ud1 := make(map[string]interface{})
	ud1["environment"] = "production"
	ud1["location"] = "datacenter-1"
	ud1["critical"] = true
	_, err = dmgr.Service.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: dev1.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for device1: %s", err)
	}

	ud2 := make(map[string]interface{})
	ud2["environment"] = "development"
	ud2["location"] = "datacenter-2"
	ud2["critical"] = false
	_, err = dmgr.Service.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: dev2.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for device2: %s", err)
	}

	ud3 := make(map[string]interface{})
	ud3["environment"] = "staging"
	ud3["location"] = "datacenter-1"
	ud3["critical"] = true
	_, err = dmgr.Service.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: dev3.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for device3: %s", err)
	}

	// Test 1: Simple equality - environment equals "production"
	found := []*models.Device{}
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

	_, err = dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Device) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDevices returned error: %s", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 device with environment=production, got %d", len(found))
	}
	if found[0].ID != dev1.ID {
		t.Fatalf("expected dev1, got %s", found[0].ID)
	}

	// Test 2: Boolean matching - critical equals true
	found = []*models.Device{}
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

	_, err = dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Device) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDevices returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 devices with critical=true, got %d", len(found))
	}

	// Test 3: AND operator - location equals "datacenter-1" AND critical equals true
	found = []*models.Device{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.location == "datacenter-1" && $.critical == true`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Device) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDevices returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 devices with datacenter-1 AND critical, got %d", len(found))
	}

	// Test 4: OR operator - environment equals "production" OR environment equals "staging"
	found = []*models.Device{}
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

	_, err = dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Device) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDevices returned error: %s", err)
	}

	if len(found) != 2 {
		t.Fatalf("expected 2 devices with production OR staging, got %d", len(found))
	}

	// Test 5: String matching with starts with
	found = []*models.Device{}
	qp = &resources.QueryParameters{
		PageSize: 25,
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.location starts with "datacenter"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	_, err = dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
		ListInput: resources.ListInput[models.Device]{
			QueryParameters: qp,
			ExhaustiveRun:   true,
			ApplyFunc: func(elem models.Device) {
				found = append(found, &elem)
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDevices returned error: %s", err)
	}

	if len(found) != 3 {
		t.Fatalf("expected 3 devices with location starting with datacenter, got %d", len(found))
	}
}
