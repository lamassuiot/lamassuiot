package devicemanager

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestGetDevicesSortByMetadataJsonPath(t *testing.T) {
	ctx := context.Background()
	dmgr, _, err := StartDeviceManagerServiceTestServer(t, false, false)
	if err != nil {
		t.Fatalf("could not create Device Manager test server: %s", err)
	}

	// Create devices with different metadata
	dev1, err := dmgr.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        "device-prod",
		Alias:     "Production Device",
		Tags:      []string{"prod"},
		Metadata:  map[string]interface{}{},
		DMSID:     "test-dms",
		Icon:      "device",
		IconColor: "#FF0000",
	})
	if err != nil {
		t.Fatalf("failed to create device-prod: %s", err)
	}

	dev2, err := dmgr.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        "device-dev",
		Alias:     "Development Device",
		Tags:      []string{"dev"},
		Metadata:  map[string]interface{}{},
		DMSID:     "test-dms",
		Icon:      "device",
		IconColor: "#00FF00",
	})
	if err != nil {
		t.Fatalf("failed to create device-dev: %s", err)
	}

	dev3, err := dmgr.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        "device-stage",
		Alias:     "Staging Device",
		Tags:      []string{"staging"},
		Metadata:  map[string]interface{}{},
		DMSID:     "test-dms",
		Icon:      "device",
		IconColor: "#0000FF",
	})
	if err != nil {
		t.Fatalf("failed to create device-stage: %s", err)
	}

	// Update metadata for device-prod
	ud1 := make(map[string]interface{})
	ud1["environment"] = "prod"
	ud1["priority"] = 10
	ud1["deployed_at"] = "2025-06-15T10:00:00Z"
	_, err = dmgr.Service.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: dev1.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud1).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for device-prod: %s", err)
	}

	// Update metadata for device-dev
	ud2 := make(map[string]interface{})
	ud2["environment"] = "dev"
	ud2["priority"] = 20
	ud2["deployed_at"] = "2026-01-10T08:00:00Z"
	_, err = dmgr.Service.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: dev2.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud2).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for device-dev: %s", err)
	}

	// Update metadata for device-stage
	ud3 := make(map[string]interface{})
	ud3["environment"] = "stage"
	ud3["priority"] = 5
	ud3["deployed_at"] = "2025-12-20T14:30:00Z"
	_, err = dmgr.Service.UpdateDeviceMetadata(ctx, services.UpdateDeviceMetadataInput{
		ID: dev3.ID,
		Patches: helpers.NewPatchBuilder().
			Add(helpers.JSONPointerBuilder(), ud3).
			Build(),
	})
	if err != nil {
		t.Fatalf("failed to update metadata for device-stage: %s", err)
	}

	// Test 1: Sort by metadata.environment (string) ascending
	t.Run("SortByEnvironmentAsc", func(t *testing.T) {
		found := []*models.Device{}
		qp := &resources.QueryParameters{
			PageSize: 25,
			Sort: resources.SortOptions{
				SortMode:     resources.SortModeAsc,
				SortField:    "metadata",
				JsonPathExpr: "$.environment",
			},
		}

		_, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
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
			t.Fatalf("expected 3 devices, got %d", len(found))
		}

		// Expected order: dev, prod, stage (alphabetical)
		if found[0].ID != "device-dev" {
			t.Errorf("expected first device to be device-dev, got %s", found[0].ID)
		}
		if found[1].ID != "device-prod" {
			t.Errorf("expected second device to be device-prod, got %s", found[1].ID)
		}
		if found[2].ID != "device-stage" {
			t.Errorf("expected third device to be device-stage, got %s", found[2].ID)
		}
	})

	// Test 2: Sort by metadata.priority (numeric) descending
	t.Run("SortByPriorityDesc", func(t *testing.T) {
		found := []*models.Device{}
		qp := &resources.QueryParameters{
			PageSize: 25,
			Sort: resources.SortOptions{
				SortMode:     resources.SortModeDesc,
				SortField:    "metadata",
				JsonPathExpr: "$.priority",
			},
		}

		_, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
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
			t.Fatalf("expected 3 devices, got %d", len(found))
		}

		// Expected order: 20 (dev), 10 (prod), 5 (stage)
		if found[0].ID != "device-dev" {
			t.Errorf("expected first device to be device-dev (priority 20), got %s", found[0].ID)
		}
		if found[1].ID != "device-prod" {
			t.Errorf("expected second device to be device-prod (priority 10), got %s", found[1].ID)
		}
		if found[2].ID != "device-stage" {
			t.Errorf("expected third device to be device-stage (priority 5), got %s", found[2].ID)
		}
	})

	// Test 3: Sort by metadata.deployed_at (date) ascending
	t.Run("SortByDeployedAtAsc", func(t *testing.T) {
		found := []*models.Device{}
		qp := &resources.QueryParameters{
			PageSize: 25,
			Sort: resources.SortOptions{
				SortMode:     resources.SortModeAsc,
				SortField:    "metadata",
				JsonPathExpr: "$.deployed_at",
			},
		}

		_, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
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
			t.Fatalf("expected 3 devices, got %d", len(found))
		}

		// Expected chronological order: prod (2025-06-15), stage (2025-12-20), dev (2026-01-10)
		if found[0].ID != "device-prod" {
			t.Errorf("expected first device to be device-prod (2025-06-15), got %s", found[0].ID)
		}
		if found[1].ID != "device-stage" {
			t.Errorf("expected second device to be device-stage (2025-12-20), got %s", found[1].ID)
		}
		if found[2].ID != "device-dev" {
			t.Errorf("expected third device to be device-dev (2026-01-10), got %s", found[2].ID)
		}
	})

	// Test 4: Pagination with JSONPath sorting
	t.Run("PaginationWithJsonPathSort", func(t *testing.T) {
		// First page with 2 items, sorted by priority ascending
		firstPage := []*models.Device{}
		qp := &resources.QueryParameters{
			PageSize: 2,
			Sort: resources.SortOptions{
				SortMode:     resources.SortModeAsc,
				SortField:    "metadata",
				JsonPathExpr: "$.priority",
			},
		}

		nextBookmark, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
			ListInput: resources.ListInput[models.Device]{
				QueryParameters: qp,
				ExhaustiveRun:   false,
				ApplyFunc: func(elem models.Device) {
					firstPage = append(firstPage, &elem)
				},
			},
		})
		if err != nil {
			t.Fatalf("GetDevices (first page) returned error: %s", err)
		}

		if len(firstPage) != 2 {
			t.Fatalf("expected 2 devices in first page, got %d", len(firstPage))
		}

		// Expected: stage (5), prod (10)
		if firstPage[0].ID != "device-stage" {
			t.Errorf("expected first item to be device-stage (priority 5), got %s", firstPage[0].ID)
		}
		if firstPage[1].ID != "device-prod" {
			t.Errorf("expected second item to be device-prod (priority 10), got %s", firstPage[1].ID)
		}

		if nextBookmark == "" {
			t.Fatal("expected non-empty bookmark for second page")
		}

		// Second page using bookmark
		secondPage := []*models.Device{}
		qp2 := &resources.QueryParameters{
			NextBookmark: nextBookmark,
			Sort: resources.SortOptions{
				SortMode:     resources.SortModeAsc,
				SortField:    "metadata",
				JsonPathExpr: "$.priority",
			},
		}

		nextBookmark2, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
			ListInput: resources.ListInput[models.Device]{
				QueryParameters: qp2,
				ExhaustiveRun:   false,
				ApplyFunc: func(elem models.Device) {
					secondPage = append(secondPage, &elem)
				},
			},
		})
		if err != nil {
			t.Fatalf("GetDevices (second page) returned error: %s", err)
		}

		if len(secondPage) != 1 {
			t.Fatalf("expected 1 device in second page, got %d", len(secondPage))
		}

		// Expected: dev (20)
		if secondPage[0].ID != "device-dev" {
			t.Errorf("expected third item to be device-dev (priority 20), got %s", secondPage[0].ID)
		}

		if nextBookmark2 != "" {
			t.Error("expected empty bookmark after last page")
		}
	})

	// Test 5: Combine filter and JSONPath sort
	t.Run("FilterAndJsonPathSort", func(t *testing.T) {
		found := []*models.Device{}
		qp := &resources.QueryParameters{
			PageSize: 25,
			Filters: []resources.FilterOption{
				{
					Field:           "metadata",
					Value:           `$.priority >= 10`,
					FilterOperation: resources.JsonPathExpression,
				},
			},
			Sort: resources.SortOptions{
				SortMode:     resources.SortModeAsc,
				SortField:    "metadata",
				JsonPathExpr: "$.priority",
			},
		}

		_, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
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
			t.Fatalf("expected 2 devices with priority >= 10, got %d", len(found))
		}

		// Expected order: prod (10), dev (20)
		if found[0].ID != "device-prod" {
			t.Errorf("expected first device to be device-prod (priority 10), got %s", found[0].ID)
		}
		if found[1].ID != "device-dev" {
			t.Errorf("expected second device to be device-dev (priority 20), got %s", found[1].ID)
		}
	})

	// Test 6: Sort by traditional field (not JSONPath)
	t.Run("TraditionalSortByStatus", func(t *testing.T) {
		found := []*models.Device{}
		qp := &resources.QueryParameters{
			PageSize: 25,
			Sort: resources.SortOptions{
				SortMode:  resources.SortModeAsc,
				SortField: "id",
			},
		}

		_, err := dmgr.HttpDeviceManagerSDK.GetDevices(ctx, services.GetDevicesInput{
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
			t.Fatalf("expected 3 devices, got %d", len(found))
		}

		// Expected alphabetical order by ID: device-dev, device-prod, device-stage
		if found[0].ID != "device-dev" {
			t.Errorf("expected first device to be device-dev, got %s", found[0].ID)
		}
		if found[1].ID != "device-prod" {
			t.Errorf("expected second device to be device-prod, got %s", found[1].ID)
		}
		if found[2].ID != "device-stage" {
			t.Errorf("expected third device to be device-stage, got %s", found[2].ID)
		}
	})
}
