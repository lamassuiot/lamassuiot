package dmsmanager

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
)

// TestGetDMSStatsFiltered is an optimized test suite that starts the server once,
// populates all test data, and then runs multiple test scenarios as subtests
func TestGetDMSStatsFiltered(t *testing.T) {
	ctx := context.Background()

	// Start server once for all subtests
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	// Populate all test data once
	setupTestData(t, ctx, dmsMgr)

	// Run all test scenarios as subtests
	t.Run("NoFilters", func(t *testing.T) {
		testNoFilters(t, ctx, dmsMgr)
	})

	t.Run("NameFilter", func(t *testing.T) {
		testNameFilter(t, ctx, dmsMgr)
	})

	t.Run("MetadataFilter", func(t *testing.T) {
		testMetadataFilter(t, ctx, dmsMgr)
	})

	t.Run("MultipleFilters", func(t *testing.T) {
		testMultipleFilters(t, ctx, dmsMgr)
	})

	t.Run("NoResults", func(t *testing.T) {
		testNoResults(t, ctx, dmsMgr)
	})

	t.Run("ViaSDK", func(t *testing.T) {
		testViaSDK(t, ctx, dmsMgr)
	})
}

// setupTestData creates all test DMSs with various properties
func setupTestData(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	// Test data structure combining all scenarios
	testDMSs := []struct {
		id       string
		name     string
		metadata map[string]any
	}{
		// For basic counting and name filters
		{
			id:   "dms-stats-1",
			name: "Production Fleet",
			metadata: map[string]any{
				"environment": "production",
				"region":      "us-east-1",
				"critical":    true,
			},
		},
		{
			id:   "dms-stats-2",
			name: "Development Fleet",
			metadata: map[string]any{
				"environment": "development",
				"region":      "us-west-2",
				"critical":    false,
			},
		},
		{
			id:   "dms-stats-3",
			name: "Testing Fleet",
			metadata: map[string]any{
				"environment": "testing",
				"region":      "eu-west-1",
				"critical":    false,
			},
		},
		// For name filter tests
		{
			id:   "dms-filter-1",
			name: "Production Server",
			metadata: map[string]any{
				"environment": "production",
				"type":        "server",
			},
		},
		{
			id:   "dms-filter-2",
			name: "Production Gateway",
			metadata: map[string]any{
				"environment": "production",
				"type":        "gateway",
			},
		},
		{
			id:   "dms-filter-3",
			name: "Development Gateway",
			metadata: map[string]any{
				"environment": "development",
				"type":        "gateway",
			},
		},
		// For metadata filter tests
		{
			id:   "dms-meta-1",
			name: "Staging DMS",
			metadata: map[string]any{
				"environment": "staging",
				"region":      "us-east-1",
				"critical":    true,
			},
		},
		// For SDK tests
		{
			id:   "dms-sdk-1",
			name: "SDK Production Fleet",
			metadata: map[string]any{
				"environment": "production",
				"sdk":         true,
			},
		},
		{
			id:   "dms-sdk-2",
			name: "SDK Development Fleet",
			metadata: map[string]any{
				"environment": "development",
				"sdk":         true,
			},
		},
	}

	// Create all DMSs
	for _, testDMS := range testDMSs {
		dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
			ID:       testDMS.id,
			Name:     testDMS.name,
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
				},
			},
		})
		if err != nil {
			t.Fatalf("failed to create DMS %s: %s", testDMS.id, err)
		}

		// Update metadata if provided
		if len(testDMS.metadata) > 0 {
			_, err = dmsMgr.Service.UpdateDMSMetadata(ctx, services.UpdateDMSMetadataInput{
				ID: dms.ID,
				Patches: helpers.NewPatchBuilder().
					Add(helpers.JSONPointerBuilder(), testDMS.metadata).
					Build(),
			})
			if err != nil {
				t.Fatalf("failed to update metadata for DMS %s: %s", testDMS.id, err)
			}
		}
	}
}

// testNoFilters verifies that GetDMSStats returns the correct total count without filters
func testNoFilters(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	stats, err := dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: nil,
	})
	if err != nil {
		t.Fatalf("GetDMSStats returned error: %s", err)
	}

	// We created 9 DMSs in setup
	assert.Equal(t, 9, stats.TotalDMSs, "expected exactly 9 DMSs without filters")
}

// testNameFilter verifies that GetDMSStats correctly filters by name
func testNameFilter(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	// Test filter by name containing "Production"
	stats, err := dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "name",
					Value:           "Production",
					FilterOperation: resources.StringContains,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with name filter returned error: %s", err)
	}

	// Should match: "Production Fleet", "Production Server", "Production Gateway", "SDK Production Fleet"
	assert.Equal(t, 4, stats.TotalDMSs, "expected exactly 4 DMSs with 'Production' in name")

	// Test filter by name containing "Gateway"
	stats, err = dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "name",
					Value:           "Gateway",
					FilterOperation: resources.StringContains,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with Gateway filter returned error: %s", err)
	}

	// Should match: "Production Gateway", "Development Gateway"
	assert.Equal(t, 2, stats.TotalDMSs, "expected exactly 2 DMSs with 'Gateway' in name")
}

// testMetadataFilter verifies that GetDMSStats correctly filters by metadata using JSONPath
func testMetadataFilter(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	// Test 1: Filter by environment = "production"
	stats, err := dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "metadata",
					Value:           `$.environment == "production"`,
					FilterOperation: resources.JsonPathExpression,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with environment filter returned error: %s", err)
	}

	// Should match 4 DMSs with environment=production
	assert.Equal(t, 4, stats.TotalDMSs, "expected exactly 4 DMSs with environment=production")

	// Test 2: Filter by critical = true
	stats, err = dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "metadata",
					Value:           `$.critical == true`,
					FilterOperation: resources.JsonPathExpression,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with critical filter returned error: %s", err)
	}

	// Should match 3 DMSs with critical=true
	assert.Equal(t, 3, stats.TotalDMSs, "expected exactly 3 DMSs with critical=true")

	// Test 3: Filter by region = "us-east-1"
	stats, err = dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "metadata",
					Value:           `$.region == "us-east-1"`,
					FilterOperation: resources.JsonPathExpression,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with region filter returned error: %s", err)
	}

	// Should match 2 DMSs in us-east-1
	assert.Equal(t, 2, stats.TotalDMSs, "expected exactly 2 DMSs in us-east-1 region")
}

// testMultipleFilters verifies that GetDMSStats correctly applies multiple filters (AND logic)
func testMultipleFilters(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	// Apply multiple filters: name contains "Production" AND metadata environment = "production"
	stats, err := dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "name",
					Value:           "Production",
					FilterOperation: resources.StringContains,
				},
				{
					Field:           "metadata",
					Value:           `$.environment == "production"`,
					FilterOperation: resources.JsonPathExpression,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with multiple filters returned error: %s", err)
	}

	// Should match exactly 4 DMSs: "Production Fleet", "Production Server", "Production Gateway", "SDK Production Fleet"
	assert.Equal(t, 4, stats.TotalDMSs, "expected exactly 4 DMSs matching both filters")
}

// testNoResults verifies that GetDMSStats returns 0 when filters match nothing
func testNoResults(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	stats, err := dmsMgr.Service.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "name",
					Value:           "NonExistentNamePattern",
					FilterOperation: resources.StringContains,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats with no-match filter returned error: %s", err)
	}

	assert.Equal(t, 0, stats.TotalDMSs, "expected 0 DMSs when filter matches nothing")
}

// testViaSDK verifies that the SDK client correctly passes filters to the service
func testViaSDK(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer) {
	// Get stats via SDK without filters
	stats, err := dmsMgr.HttpDeviceManagerSDK.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: nil,
	})
	if err != nil {
		t.Fatalf("GetDMSStats via SDK returned error: %s", err)
	}

	// Should return all 9 DMSs
	assert.Equal(t, 9, stats.TotalDMSs, "expected exactly 9 DMSs via SDK")

	// Get stats via SDK with name filter
	stats, err = dmsMgr.HttpDeviceManagerSDK.GetDMSStats(ctx, services.GetDMSStatsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "name",
					Value:           "SDK",
					FilterOperation: resources.StringContains,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("GetDMSStats via SDK with filter returned error: %s", err)
	}

	// Should match exactly 2 DMSs with "SDK" in name
	assert.Equal(t, 2, stats.TotalDMSs, "expected exactly 2 DMSs matching SDK filter via SDK")
}
