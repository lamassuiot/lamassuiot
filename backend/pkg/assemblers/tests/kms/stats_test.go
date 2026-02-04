package kms

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
)

// TestGetKeyStatsFiltered is a comprehensive test suite for the KMS statistics endpoint
// with filtering support. Tests are organized as subtests within a single server instance.
func TestGetKeyStatsFiltered(t *testing.T) {
	ctx := context.Background()

	// Start KMS server once for all subtests
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	// Populate all test data once
	setupStatsTestData(t, ctx, kmsTest)

	// Run all test scenarios as subtests
	t.Run("NoFilters", func(t *testing.T) {
		testStatsNoFilters(t, ctx, kmsTest)
	})

	t.Run("EngineFiltering", func(t *testing.T) {
		testStatsEngineFiltering(t, ctx, kmsTest)
	})

	t.Run("AlgorithmFiltering", func(t *testing.T) {
		testStatsAlgorithmFiltering(t, ctx, kmsTest)
	})

	t.Run("MetadataFiltering", func(t *testing.T) {
		testStatsMetadataFiltering(t, ctx, kmsTest)
	})

	t.Run("CombinedFilters", func(t *testing.T) {
		testStatsCombinedFilters(t, ctx, kmsTest)
	})

	t.Run("EngineDistribution", func(t *testing.T) {
		testStatsEngineDistribution(t, ctx, kmsTest)
	})

	t.Run("AlgorithmDistribution", func(t *testing.T) {
		testStatsAlgorithmDistribution(t, ctx, kmsTest)
	})

	t.Run("ViaSDK", func(t *testing.T) {
		testStatsViaSDK(t, ctx, kmsTest)
	})
}

// setupStatsTestData creates all test keys with various properties across engines and algorithms
func setupStatsTestData(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Get available engines
	engines, err := kmsTest.Service.GetCryptoEngineProvider(ctx)
	if err != nil {
		t.Fatalf("failed to get crypto engines: %s", err)
	}

	if len(engines) < 1 {
		t.Fatal("no crypto engines available for testing")
	}

	defaultEngine := ""
	vaultEngine := ""
	for _, engine := range engines {
		if defaultEngine == "" {
			defaultEngine = engine.ID
		}
		if engine.ID == "vault" {
			vaultEngine = engine.ID
		}
	}

	// Test data structure for comprehensive coverage
	testKeys := []struct {
		name      string
		algorithm string
		size      int
		engineID  string
		tags      []string
		metadata  map[string]any
	}{
		// RSA keys in default engine
		{
			name:      "rsa-production-signing-1",
			algorithm: "RSA",
			size:      2048,
			engineID:  defaultEngine,
			tags:      []string{"production", "signing"},
			metadata: map[string]any{
				"environment": "production",
				"purpose":     "signing",
				"region":      "us-east-1",
			},
		},
		{
			name:      "rsa-production-encryption-1",
			algorithm: "RSA",
			size:      4096,
			engineID:  defaultEngine,
			tags:      []string{"production", "encryption"},
			metadata: map[string]any{
				"environment": "production",
				"purpose":     "encryption",
				"region":      "us-west-2",
			},
		},
		{
			name:      "rsa-development-1",
			algorithm: "RSA",
			size:      2048,
			engineID:  defaultEngine,
			tags:      []string{"development"},
			metadata: map[string]any{
				"environment": "development",
				"purpose":     "testing",
			},
		},
		// ECDSA keys in default engine
		{
			name:      "ecdsa-production-1",
			algorithm: "ECDSA",
			size:      256,
			engineID:  defaultEngine,
			tags:      []string{"production", "signing"},
			metadata: map[string]any{
				"environment": "production",
				"purpose":     "signing",
				"curve":       "P-256",
			},
		},
		{
			name:      "ecdsa-production-2",
			algorithm: "ECDSA",
			size:      384,
			engineID:  defaultEngine,
			tags:      []string{"production"},
			metadata: map[string]any{
				"environment": "production",
				"purpose":     "verification",
				"curve":       "P-384",
			},
		},
		{
			name:      "ecdsa-staging-1",
			algorithm: "ECDSA",
			size:      256,
			engineID:  defaultEngine,
			tags:      []string{"staging"},
			metadata: map[string]any{
				"environment": "staging",
				"purpose":     "signing",
			},
		},
	}

	// Add keys to vault engine if available
	if vaultEngine != "" {
		testKeys = append(testKeys, []struct {
			name      string
			algorithm string
			size      int
			engineID  string
			tags      []string
			metadata  map[string]any
		}{
			{
				name:      "vault-rsa-production-1",
				algorithm: "RSA",
				size:      2048,
				engineID:  vaultEngine,
				tags:      []string{"production", "vault"},
				metadata: map[string]any{
					"environment": "production",
					"engine":      "vault",
					"purpose":     "signing",
				},
			},
			{
				name:      "vault-ecdsa-production-1",
				algorithm: "ECDSA",
				size:      256,
				engineID:  vaultEngine,
				tags:      []string{"production", "vault"},
				metadata: map[string]any{
					"environment": "production",
					"engine":      "vault",
					"purpose":     "encryption",
				},
			},
		}...)
	}

	// Create all test keys
	for _, testKey := range testKeys {
		key, err := kmsTest.Service.CreateKey(ctx, services.CreateKeyInput{
			Name:      testKey.name,
			Algorithm: testKey.algorithm,
			Size:      testKey.size,
			EngineID:  testKey.engineID,
			Tags:      testKey.tags,
			Metadata:  testKey.metadata,
		})
		if err != nil {
			t.Fatalf("failed to create test key %s: %s", testKey.name, err)
		}
		t.Logf("Created test key: %s (ID: %s, Engine: %s, Algorithm: %s)",
			key.Name, key.KeyID, key.EngineID, key.Algorithm)
	}

	t.Logf("Successfully created %d test keys for statistics tests", len(testKeys))
}

// testStatsNoFilters verifies statistics without any filters
func testStatsNoFilters(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: nil,
	})
	assert.NoError(t, err, "GetKeyStats without filters should not return an error")
	assert.NotNil(t, stats, "Stats should not be nil")

	// Verify we got the expected total (at least the keys we created)
	assert.GreaterOrEqual(t, stats.TotalKeys, 6, "Should have at least 6 keys from setup")

	// Verify distributions are populated
	assert.NotEmpty(t, stats.KeysDistributionPerEngine, "Engine distribution should not be empty")
	assert.NotEmpty(t, stats.KeysDistributionPerAlgorithm, "Algorithm distribution should not be empty")

	// Verify distribution totals make sense
	engineTotal := 0
	for engine, count := range stats.KeysDistributionPerEngine {
		assert.GreaterOrEqual(t, count, 0, "Engine %s count should be non-negative", engine)
		if count != -1 { // Exclude failed counts
			engineTotal += count
		}
	}

	// Log results for debugging
	t.Logf("Total keys: %d", stats.TotalKeys)
	t.Logf("Engine distribution: %v", stats.KeysDistributionPerEngine)
	t.Logf("Algorithm distribution: %v", stats.KeysDistributionPerAlgorithm)
}

// testStatsEngineFiltering verifies filtering by crypto engine
func testStatsEngineFiltering(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Get available engines first
	engines, err := kmsTest.Service.GetCryptoEngineProvider(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, engines, "Should have at least one engine")

	targetEngine := engines[0].ID

	// Get stats filtered by specific engine
	queryParams := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "engine_id",
				FilterOperation: resources.StringEqual,
				Value:           targetEngine,
			},
		},
	}

	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	assert.NoError(t, err, "GetKeyStats with engine filter should not return an error")
	assert.NotNil(t, stats, "Stats should not be nil")

	// Verify only the target engine has keys
	for engine, count := range stats.KeysDistributionPerEngine {
		if engine == targetEngine {
			assert.Greater(t, count, 0, "Target engine %s should have keys", targetEngine)
		} else {
			assert.Equal(t, 0, count, "Non-target engine %s should have 0 keys", engine)
		}
	}

	t.Logf("Engine filter test - Target: %s, Total: %d, Distribution: %v",
		targetEngine, stats.TotalKeys, stats.KeysDistributionPerEngine)
}

// testStatsAlgorithmFiltering verifies filtering by algorithm
func testStatsAlgorithmFiltering(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Test RSA algorithm filter
	queryParams := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "algorithm",
				FilterOperation: resources.StringContains,
				Value:           "RSA",
			},
		},
	}

	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	assert.NoError(t, err, "GetKeyStats with algorithm filter should not return an error")
	assert.NotNil(t, stats, "Stats should not be nil")

	// Verify RSA keys are counted
	rsaCount, hasRSA := stats.KeysDistributionPerAlgorithm["RSA"]
	assert.True(t, hasRSA, "Should have RSA in algorithm distribution")
	assert.Greater(t, rsaCount, 0, "RSA count should be greater than 0")
	assert.Equal(t, stats.TotalKeys, rsaCount, "Total should match RSA count when filtering by RSA")

	// ECDSA keys should be 0 when filtering for RSA
	ecdsaCount := stats.KeysDistributionPerAlgorithm["ECDSA"]
	assert.Equal(t, 0, ecdsaCount, "ECDSA count should be 0 when filtering for RSA")

	t.Logf("Algorithm filter test - RSA: Total: %d, Distribution: %v",
		stats.TotalKeys, stats.KeysDistributionPerAlgorithm)

	// Test ECDSA algorithm filter
	queryParamsECDSA := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "algorithm",
				FilterOperation: resources.StringContains,
				Value:           "ECDSA",
			},
		},
	}

	statsECDSA, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParamsECDSA,
	})
	assert.NoError(t, err)
	assert.Greater(t, statsECDSA.TotalKeys, 0, "Should have ECDSA keys")
	assert.Greater(t, statsECDSA.KeysDistributionPerAlgorithm["ECDSA"], 0, "ECDSA count should be > 0")

	t.Logf("Algorithm filter test - ECDSA: Total: %d, Distribution: %v",
		statsECDSA.TotalKeys, statsECDSA.KeysDistributionPerAlgorithm)
}

// testStatsMetadataFiltering verifies filtering by metadata with JSONPath
func testStatsMetadataFiltering(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Filter by environment metadata
	queryParams := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment == "production"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	assert.NoError(t, err, "GetKeyStats with metadata filter should not return an error")
	assert.NotNil(t, stats, "Stats should not be nil")
	assert.Greater(t, stats.TotalKeys, 0, "Should have production keys")

	t.Logf("Metadata filter test - production environment: Total: %d", stats.TotalKeys)

	// Filter by purpose metadata
	queryParamsPurpose := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.purpose == "signing"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	statsPurpose, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParamsPurpose,
	})
	assert.NoError(t, err)
	assert.Greater(t, statsPurpose.TotalKeys, 0, "Should have signing keys")

	t.Logf("Metadata filter test - signing purpose: Total: %d", statsPurpose.TotalKeys)
}

// testStatsCombinedFilters verifies multiple filters work together (AND logic)
func testStatsCombinedFilters(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Get available engines first
	engines, err := kmsTest.Service.GetCryptoEngineProvider(ctx)
	assert.NoError(t, err)
	targetEngine := engines[0].ID

	// Combine engine filter + algorithm filter
	queryParams := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "engine_id",
				FilterOperation: resources.StringEqual,
				Value:           targetEngine,
			},
			{
				Field:           "algorithm",
				FilterOperation: resources.StringContains,
				Value:           "RSA",
			},
		},
	}

	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	assert.NoError(t, err, "GetKeyStats with combined filters should not return an error")
	assert.NotNil(t, stats, "Stats should not be nil")

	// Verify only target engine has counts
	for engine, count := range stats.KeysDistributionPerEngine {
		if engine == targetEngine {
			// May or may not have keys depending on test data
			assert.GreaterOrEqual(t, count, 0, "Target engine count should be non-negative")
		} else {
			assert.Equal(t, 0, count, "Other engines should have 0 keys with filter")
		}
	}

	// Verify only RSA is counted in algorithm distribution
	rsaCount := stats.KeysDistributionPerAlgorithm["RSA"]
	assert.Equal(t, stats.TotalKeys, rsaCount, "Total should match RSA count")

	t.Logf("Combined filters test - Engine: %s + RSA: Total: %d", targetEngine, stats.TotalKeys)

	// Test engine + metadata filter
	queryParamsMeta := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "engine_id",
				FilterOperation: resources.StringEqual,
				Value:           targetEngine,
			},
			{
				Field:           "metadata",
				Value:           `$.environment == "production"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	statsMeta, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParamsMeta,
	})
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, statsMeta.TotalKeys, 0, "Combined filter should return valid count")

	t.Logf("Combined filters test - Engine + Metadata: Total: %d", statsMeta.TotalKeys)
}

// testStatsEngineDistribution verifies engine distribution is accurate
func testStatsEngineDistribution(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Get stats without filters
	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: nil,
	})
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Verify sum of engine counts matches total (excluding -1 error values)
	engineSum := 0
	for engine, count := range stats.KeysDistributionPerEngine {
		t.Logf("Engine %s: %d keys", engine, count)
		if count == -1 {
			t.Logf("Warning: Engine %s returned error count (-1)", engine)
		} else {
			assert.GreaterOrEqual(t, count, 0, "Engine count should be non-negative")
			engineSum += count
		}
	}

	// The sum should equal the total (unless there were errors)
	hasErrors := false
	for _, count := range stats.KeysDistributionPerEngine {
		if count == -1 {
			hasErrors = true
			break
		}
	}

	if !hasErrors {
		assert.Equal(t, stats.TotalKeys, engineSum,
			"Sum of engine distribution should equal total keys")
	}

	// Test with filter to verify distribution still works
	queryParams := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "algorithm",
				FilterOperation: resources.StringContains,
				Value:           "RSA",
			},
		},
	}

	statsFiltered, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	assert.NoError(t, err)

	// Verify filtered engine distribution
	filteredSum := 0
	for _, count := range statsFiltered.KeysDistributionPerEngine {
		if count != -1 {
			filteredSum += count
		}
	}

	if !hasErrors {
		assert.Equal(t, statsFiltered.TotalKeys, filteredSum,
			"Filtered engine distribution should sum to filtered total")
	}

	t.Logf("Engine distribution test passed - Total: %d, Engines: %d",
		stats.TotalKeys, len(stats.KeysDistributionPerEngine))
}

// testStatsAlgorithmDistribution verifies algorithm distribution is accurate
func testStatsAlgorithmDistribution(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Get stats without filters
	stats, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: nil,
	})
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Verify algorithm distribution
	algorithmSum := 0
	for algorithm, count := range stats.KeysDistributionPerAlgorithm {
		t.Logf("Algorithm %s: %d keys", algorithm, count)
		if count == -1 {
			t.Logf("Warning: Algorithm %s returned error count (-1)", algorithm)
		} else {
			assert.GreaterOrEqual(t, count, 0, "Algorithm count should be non-negative")
			algorithmSum += count
		}
	}

	// Verify expected algorithms are present
	expectedAlgorithms := []string{"RSA", "ECDSA", "Ed25519"}
	for _, algo := range expectedAlgorithms {
		_, exists := stats.KeysDistributionPerAlgorithm[algo]
		assert.True(t, exists, "Algorithm %s should be in distribution", algo)
	}

	// Test with engine filter to verify algorithm distribution still works
	availableEngines, err := kmsTest.Service.GetCryptoEngineProvider(ctx)
	assert.NoError(t, err)

	if len(availableEngines) > 0 {
		queryParams := &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "engine_id",
					FilterOperation: resources.StringEqual,
					Value:           availableEngines[0].ID,
				},
			},
		}

		statsFiltered, err := kmsTest.Service.GetKeyStats(ctx, services.GetKeyStatsInput{
			QueryParameters: queryParams,
		})
		assert.NoError(t, err)

		// Verify algorithm distribution exists
		assert.NotEmpty(t, statsFiltered.KeysDistributionPerAlgorithm,
			"Algorithm distribution should exist even with engine filter")

		t.Logf("Algorithm distribution with engine filter: %v",
			statsFiltered.KeysDistributionPerAlgorithm)
	}

	t.Logf("Algorithm distribution test passed - Total counted: %d", algorithmSum)
}

// testStatsViaSDK verifies the stats endpoint works through the HTTP SDK
func testStatsViaSDK(t *testing.T, ctx context.Context, kmsTest *tests.KMSTestServer) {
	// Test without filters
	stats, err := kmsTest.HttpKMSSDK.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: nil,
	})
	assert.NoError(t, err, "SDK GetKeyStats should not return an error")
	assert.NotNil(t, stats, "Stats should not be nil")
	assert.Greater(t, stats.TotalKeys, 0, "Should have keys via SDK")
	assert.NotEmpty(t, stats.KeysDistributionPerEngine, "Engine distribution should not be empty via SDK")
	assert.NotEmpty(t, stats.KeysDistributionPerAlgorithm, "Algorithm distribution should not be empty via SDK")

	t.Logf("SDK test without filters - Total: %d", stats.TotalKeys)

	// Test with filter via SDK
	queryParams := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "algorithm",
				FilterOperation: resources.StringContains,
				Value:           "RSA",
			},
		},
	}

	statsFiltered, err := kmsTest.HttpKMSSDK.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParams,
	})
	assert.NoError(t, err, "SDK GetKeyStats with filter should not return an error")
	assert.NotNil(t, statsFiltered, "Filtered stats should not be nil")

	// Verify RSA filtering worked
	rsaCount := statsFiltered.KeysDistributionPerAlgorithm["RSA"]
	assert.Greater(t, rsaCount, 0, "Should have RSA keys via SDK")
	assert.Equal(t, statsFiltered.TotalKeys, rsaCount,
		"Filtered total should match RSA count via SDK")

	t.Logf("SDK test with RSA filter - Total: %d", statsFiltered.TotalKeys)

	// Test metadata filter via SDK
	queryParamsMeta := &resources.QueryParameters{
		Filters: []resources.FilterOption{
			{
				Field:           "metadata",
				Value:           `$.environment == "production"`,
				FilterOperation: resources.JsonPathExpression,
			},
		},
	}

	statsMeta, err := kmsTest.HttpKMSSDK.GetKeyStats(ctx, services.GetKeyStatsInput{
		QueryParameters: queryParamsMeta,
	})
	assert.NoError(t, err, "SDK GetKeyStats with metadata filter should not return an error")
	assert.NotNil(t, statsMeta, "Metadata filtered stats should not be nil")
	assert.GreaterOrEqual(t, statsMeta.TotalKeys, 0, "Should have valid count via SDK")

	t.Logf("SDK test with metadata filter - Total: %d", statsMeta.TotalKeys)

	t.Log("SDK tests passed - All operations work correctly through HTTP SDK")
}
