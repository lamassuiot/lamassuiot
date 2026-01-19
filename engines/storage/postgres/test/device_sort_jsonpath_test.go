package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDeviceSortByJsonPath(t *testing.T) {
	_, suite := BeforeSuite([]string{"devicemanager"}, false)
	defer suite.AfterSuite()

	db := suite.DB["devicemanager"]
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.TraceLevel)

	// Migrate the schema
	migrator := postgres.NewMigrator(logger, db)
	migrator.MigrateToLatest()

	// Initialize the repository
	repo, err := postgres.NewDeviceManagerRepository(logger, db)
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}

	// Clean up before test
	suite.BeforeEach()

	// Insert test data: 3 devices with different metadata
	devices := []models.Device{
		{
			ID: "device_prod",
			Metadata: map[string]any{
				"env":      "prod",
				"priority": float64(10), // JSON numbers are float64
			},
			Status:            models.DeviceActive,
			CreationTimestamp: time.Now(),
			Tags:              []string{},
			Events:            map[time.Time]models.DeviceEvent{},
			ExtraSlots:        map[string]*models.Slot[any]{},
		},
		{
			ID: "device_dev",
			Metadata: map[string]any{
				"env":      "dev",
				"priority": float64(20),
			},
			Status:            models.DeviceActive,
			CreationTimestamp: time.Now(),
			Tags:              []string{},
			Events:            map[time.Time]models.DeviceEvent{},
			ExtraSlots:        map[string]*models.Slot[any]{},
		},
		{
			ID: "device_stage",
			Metadata: map[string]any{
				"env":      "stage",
				"priority": float64(5),
			},
			Status:            models.DeviceActive,
			CreationTimestamp: time.Now(),
			Tags:              []string{},
			Events:            map[time.Time]models.DeviceEvent{},
			ExtraSlots:        map[string]*models.Slot[any]{},
		},
	}

	for _, d := range devices {
		if err := db.Create(&d).Error; err != nil {
			t.Fatalf("Failed to create device %s: %v", d.ID, err)
		}
	}

	// Test Case 1: Sort by metadata.env ASC
	// Expected order: dev, prod, stage (alphabetical)
	t.Run("SortByEnvAsc", func(t *testing.T) {
		queryParams := &resources.QueryParameters{
			Sort: resources.SortOptions{
				SortField:    "metadata",
				SortMode:     resources.SortModeAsc,
				JsonPathExpr: "$.env",
			},
			PageSize: 10,
		}

		var result []models.Device
		_, err := repo.SelectAll(context.Background(), false, func(d models.Device) {
			result = append(result, d)
		}, queryParams, nil)

		if err != nil {
			t.Fatalf("SelectAll failed: %v", err)
		}

		assert.Equal(t, 3, len(result), "Expected 3 devices")
		assert.Equal(t, "device_dev", result[0].ID, "Expected first device to be device_dev")
		assert.Equal(t, "device_prod", result[1].ID, "Expected second device to be device_prod")
		assert.Equal(t, "device_stage", result[2].ID, "Expected third device to be device_stage")
	})

	// Test Case 2: Sort by metadata.priority DESC
	// Expected order: dev (20), prod (10), stage (5)
	t.Run("SortByPriorityDesc", func(t *testing.T) {
		queryParams := &resources.QueryParameters{
			Sort: resources.SortOptions{
				SortField:    "metadata",
				SortMode:     resources.SortModeDesc,
				JsonPathExpr: "$.priority",
			},
			PageSize: 10,
		}

		var result []models.Device
		_, err := repo.SelectAll(context.Background(), false, func(d models.Device) {
			result = append(result, d)
		}, queryParams, nil)

		if err != nil {
			t.Fatalf("SelectAll failed: %v", err)
		}

		assert.Equal(t, 3, len(result), "Expected 3 devices")
		assert.Equal(t, "device_dev", result[0].ID, "Expected first device to be device_dev (priority 20)")
		assert.Equal(t, "device_prod", result[1].ID, "Expected second device to be device_prod (priority 10)")
		assert.Equal(t, "device_stage", result[2].ID, "Expected third device to be device_stage (priority 5)")
	})

	// Test Case 3: Test pagination bookmark handling with JSONPath
	t.Run("PaginationWithJsonPath", func(t *testing.T) {
		queryParams := &resources.QueryParameters{
			Sort: resources.SortOptions{
				SortField:    "metadata",
				SortMode:     resources.SortModeAsc,
				JsonPathExpr: "$.priority",
			},
			PageSize: 2, // Get only 2 devices per page
		}

		// First page
		var firstPage []models.Device
		bookmark, err := repo.SelectAll(context.Background(), false, func(d models.Device) {
			firstPage = append(firstPage, d)
		}, queryParams, nil)

		if err != nil {
			t.Fatalf("SelectAll (first page) failed: %v", err)
		}

		assert.Equal(t, 2, len(firstPage), "Expected 2 devices in first page")
		assert.NotEmpty(t, bookmark, "Expected non-empty bookmark for pagination")

		// Second page using bookmark
		queryParams.NextBookmark = bookmark
		var secondPage []models.Device
		bookmark2, err := repo.SelectAll(context.Background(), false, func(d models.Device) {
			secondPage = append(secondPage, d)
		}, queryParams, nil)

		if err != nil {
			t.Fatalf("SelectAll (second page) failed: %v", err)
		}

		assert.Equal(t, 1, len(secondPage), "Expected 1 device in second page")
		assert.Empty(t, bookmark2, "Expected empty bookmark (no more pages)")

		// Verify order across pages: stage (5), prod (10), dev (20)
		assert.Equal(t, "device_stage", firstPage[0].ID, "First item should be device_stage")
		assert.Equal(t, "device_prod", firstPage[1].ID, "Second item should be device_prod")
		assert.Equal(t, "device_dev", secondPage[0].ID, "Third item should be device_dev")
	})

	t.Run("SortByDateAsc", func(t *testing.T) {
		// Clean up before this test
		suite.BeforeEach()

		// Create devices with dates in metadata
		devices := []models.Device{
			{
				ID: "device_new",
				Metadata: map[string]any{
					"created_at": "2026-01-15T10:00:00Z",
				},
				Status:            models.DeviceActive,
				CreationTimestamp: time.Now(),
				Tags:              []string{},
				Events:            map[time.Time]models.DeviceEvent{},
				ExtraSlots:        map[string]*models.Slot[any]{},
			},
			{
				ID: "device_old",
				Metadata: map[string]any{
					"created_at": "2025-01-10T08:30:00Z",
				},
				Status:            models.DeviceActive,
				CreationTimestamp: time.Now(),
				Tags:              []string{},
				Events:            map[time.Time]models.DeviceEvent{},
				ExtraSlots:        map[string]*models.Slot[any]{},
			},
			{
				ID: "device_mid",
				Metadata: map[string]any{
					"created_at": "2025-06-20T14:15:00Z",
				},
				Status:            models.DeviceActive,
				CreationTimestamp: time.Now(),
				Tags:              []string{},
				Events:            map[time.Time]models.DeviceEvent{},
				ExtraSlots:        map[string]*models.Slot[any]{},
			},
		}

		for _, dev := range devices {
			if err := db.Create(&dev).Error; err != nil {
				t.Fatalf("Failed to insert device: %v", err)
			}
		}

		// Query with JSONPath sort by created_at date ascending
		queryParams := &resources.QueryParameters{
			Sort: resources.SortOptions{
				SortField:    "metadata",
				SortMode:     resources.SortModeAsc,
				JsonPathExpr: "$.created_at",
			},
			PageSize: 10,
		}

		var result []models.Device
		_, err = repo.SelectAll(context.Background(), false, func(d models.Device) {
			result = append(result, d)
		}, queryParams, nil)

		if err != nil {
			t.Fatalf("SelectAll failed: %v", err)
		}

		assert.Equal(t, 3, len(result), "Expected 3 devices")

		// Verify chronological order: old -> mid -> new
		assert.Equal(t, "device_old", result[0].ID)
		assert.Equal(t, "device_mid", result[1].ID)
		assert.Equal(t, "device_new", result[2].ID)
	})
}
