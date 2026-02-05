package postgrestest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	pconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateDatabaseCADatabase(t *testing.T) {
	// Setup test database
	cfg, suite := BeforeSuite([]string{postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Run migration
	err := postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA)
	require.NoError(t, err, "migration should succeed")

	// Verify migration was applied by checking goose_db_version table
	var count int64
	suite.DB[postgres.CA_SCHEMA].Table("goose_db_version").Count(&count)
	assert.Greater(t, count, int64(0), "should have migration version records")
}

func TestMigrateDatabaseAllDatabases(t *testing.T) {
	tests := []struct {
		name   string
		dbName string
	}{
		{"CA database", postgres.CA_SCHEMA},
		{"Device Manager database", postgres.DEVICE_SCHEMA},
		{"DMS Manager database", postgres.DMS_SCHEMA},
		{"Alerts database", postgres.ALERTS_SCHEMA},
		{"VA database", postgres.VA_SCHEMA},
		{"KMS database", postgres.KMS_SCHEMA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			cfg, suite := BeforeSuite([]string{tt.dbName}, false)
			defer suite.AfterSuite()

			logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

			// Run migration
			err := postgres.MigrateDatabase(logger, cfg, tt.dbName)
			require.NoError(t, err, "migration should succeed for %s", tt.dbName)

			// Verify migration was applied
			var count int64
			suite.DB[tt.dbName].Table("goose_db_version").Count(&count)
			assert.Greater(t, count, int64(0), "should have migration version records for %s", tt.dbName)
		})
	}
}

func TestMigrateDatabaseIdempotency(t *testing.T) {
	// Setup test database
	cfg, suite := BeforeSuite([]string{postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Run migration first time
	err := postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA)
	require.NoError(t, err)

	// Get version after first migration
	var firstVersionCount int64
	suite.DB[postgres.CA_SCHEMA].Table("goose_db_version").Count(&firstVersionCount)

	// Run migration second time (should be idempotent)
	err = postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA)
	require.NoError(t, err)

	// Get version after second migration
	var secondVersionCount int64
	suite.DB[postgres.CA_SCHEMA].Table("goose_db_version").Count(&secondVersionCount)

	// Should have same number of versions
	assert.Equal(t, firstVersionCount, secondVersionCount, "migrations should be idempotent")
}

func TestMigrateDatabaseInvalidConnection(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Use invalid connection configuration
	cfg := pconfig.PostgresPSEConfig{
		Hostname: "invalid-host-that-does-not-exist",
		Port:     9999,
		Username: "invalid",
		Password: "invalid",
	}

	err := postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not create postgres connection")
}

func TestMigrateAllDatabases(t *testing.T) {
	// Setup all test databases
	allDatabases := []string{
		postgres.CA_SCHEMA,
		postgres.DEVICE_SCHEMA,
		postgres.DMS_SCHEMA,
		postgres.ALERTS_SCHEMA,
		postgres.VA_SCHEMA,
		postgres.KMS_SCHEMA,
	}

	cfg, suite := BeforeSuite(allDatabases, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Run migration on all databases
	err := postgres.MigrateAllDatabases(logger, cfg)
	require.NoError(t, err)

	// Verify all databases were migrated
	for _, dbName := range allDatabases {
		var count int64
		suite.DB[dbName].Table("goose_db_version").Count(&count)
		assert.Greater(t, count, int64(0), "database %s should have migration version records", dbName)
	}
}

func TestMigrateAllDatabasesIdempotency(t *testing.T) {
	// Setup all test databases
	allDatabases := []string{
		postgres.CA_SCHEMA,
		postgres.DEVICE_SCHEMA,
		postgres.DMS_SCHEMA,
		postgres.ALERTS_SCHEMA,
		postgres.VA_SCHEMA,
		postgres.KMS_SCHEMA,
	}

	cfg, suite := BeforeSuite(allDatabases, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Run migration first time
	err := postgres.MigrateAllDatabases(logger, cfg)
	require.NoError(t, err)

	// Get version counts after first migration
	firstVersionCounts := make(map[string]int64)
	for _, dbName := range allDatabases {
		var count int64
		suite.DB[dbName].Table("goose_db_version").Count(&count)
		firstVersionCounts[dbName] = count
	}

	// Run migration second time (should be idempotent)
	err = postgres.MigrateAllDatabases(logger, cfg)
	require.NoError(t, err)

	// Get version counts after second migration
	secondVersionCounts := make(map[string]int64)
	for _, dbName := range allDatabases {
		var count int64
		suite.DB[dbName].Table("goose_db_version").Count(&count)
		secondVersionCounts[dbName] = count
	}

	// All databases should have same version counts
	for _, dbName := range allDatabases {
		assert.Equal(t, firstVersionCounts[dbName], secondVersionCounts[dbName],
			"database %s migrations should be idempotent", dbName)
	}
}

func TestMigrateAllDatabasesPartialFailure(t *testing.T) {
	// Setup only some databases (to simulate partial environment)
	availableDatabases := []string{
		postgres.CA_SCHEMA,
		postgres.DEVICE_SCHEMA,
	}

	cfg, suite := BeforeSuite(availableDatabases, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// This should fail because not all databases exist
	err := postgres.MigrateAllDatabases(logger, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to migrate database")
}

func TestGetDatabaseVersion(t *testing.T) {
	tests := []struct {
		name   string
		dbName string
	}{
		{"CA database", postgres.CA_SCHEMA},
		{"Device Manager database", postgres.DEVICE_SCHEMA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			cfg, suite := BeforeSuite([]string{tt.dbName}, false)
			defer suite.AfterSuite()

			logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

			// Get version before migration
			currentBefore, targetBefore, err := postgres.GetDatabaseVersion(logger, cfg, tt.dbName)
			require.NoError(t, err)
			assert.Equal(t, int64(0), currentBefore, "current version should be 0 before migration")
			assert.Greater(t, targetBefore, int64(0), "target version should be greater than 0")

			// Run migration
			err = postgres.MigrateDatabase(logger, cfg, tt.dbName)
			require.NoError(t, err)

			// Get version after migration
			currentAfter, targetAfter, err := postgres.GetDatabaseVersion(logger, cfg, tt.dbName)
			require.NoError(t, err)
			assert.Equal(t, targetAfter, currentAfter, "current version should equal target version after migration")
			assert.Greater(t, currentAfter, currentBefore, "current version should increase after migration")
		})
	}
}

func TestGetDatabaseVersionInvalidConnection(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Use invalid connection configuration
	cfg := pconfig.PostgresPSEConfig{
		Hostname: "invalid-host-that-does-not-exist",
		Port:     9999,
		Username: "invalid",
		Password: "invalid",
	}

	current, target, err := postgres.GetDatabaseVersion(logger, cfg, postgres.CA_SCHEMA)
	require.Error(t, err)
	assert.Equal(t, int64(0), current)
	assert.Equal(t, int64(0), target)
	assert.Contains(t, err.Error(), "could not create postgres connection")
}

func TestMigrationProgress(t *testing.T) {
	// Setup test database
	cfg, suite := BeforeSuite([]string{postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

	// Get initial state
	currentBefore, targetBefore, err := postgres.GetDatabaseVersion(logger, cfg, postgres.CA_SCHEMA)
	require.NoError(t, err)

	// Should start at version 0
	assert.Equal(t, int64(0), currentBefore, "should start at version 0")
	assert.Greater(t, targetBefore, int64(0), "should have pending migrations")

	// Apply migrations
	err = postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA)
	require.NoError(t, err)

	// Get final state
	currentAfter, targetAfter, err := postgres.GetDatabaseVersion(logger, cfg, postgres.CA_SCHEMA)
	require.NoError(t, err)

	// Should be at target version
	assert.Equal(t, targetAfter, currentAfter, "should reach target version")
	assert.Equal(t, targetBefore, targetAfter, "target version should not change")

	// Verify goose_db_version table has correct records
	type gooseVersion struct {
		ID        int64  `gorm:"column:id"`
		VersionID int64  `gorm:"column:version_id"`
		IsApplied bool   `gorm:"column:is_applied"`
		Tstamp    string `gorm:"column:tstamp"`
	}

	var versions []gooseVersion
	err = suite.DB[postgres.CA_SCHEMA].Table("goose_db_version").Order("version_id").Find(&versions).Error
	require.NoError(t, err)

	// All migrations should be applied
	for _, v := range versions {
		assert.True(t, v.IsApplied, "version %d should be applied", v.VersionID)
	}

	// The highest version should match our target
	if len(versions) > 0 {
		lastVersion := versions[len(versions)-1]
		assert.Equal(t, targetAfter, lastVersion.VersionID, "last version should match target")
	}
}

func TestMigrationTablesCreated(t *testing.T) {
	tests := []struct {
		name           string
		dbName         string
		expectedTables []string
	}{
		{
			name:   "CA database creates correct tables",
			dbName: postgres.CA_SCHEMA,
			expectedTables: []string{
				"ca_certificates",
				"certificates",
				"issuance_profiles",
				"goose_db_version",
			},
		},
		{
			name:   "Device Manager database creates correct tables",
			dbName: postgres.DEVICE_SCHEMA,
			expectedTables: []string{
				"devices",
				"goose_db_version",
			},
		},
		{
			name:   "DMS Manager database creates correct tables",
			dbName: postgres.DMS_SCHEMA,
			expectedTables: []string{
				"dms",
				"goose_db_version",
			},
		},
		{
			name:   "Alerts database creates correct tables",
			dbName: postgres.ALERTS_SCHEMA,
			expectedTables: []string{
				"subscriptions",
				"events",
				"goose_db_version",
			},
		},
		{
			name:   "KMS database creates correct tables",
			dbName: postgres.KMS_SCHEMA,
			expectedTables: []string{
				"kms_keys",
				"goose_db_version",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			cfg, suite := BeforeSuite([]string{tt.dbName}, false)
			defer suite.AfterSuite()

			logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")

			// Run migration
			err := postgres.MigrateDatabase(logger, cfg, tt.dbName)
			require.NoError(t, err)

			// Get all tables
			var tables []string
			err = suite.DB[tt.dbName].Table("information_schema.tables").
				Where("table_schema = ?", "public").
				Pluck("table_name", &tables).Error
			require.NoError(t, err)

			// Verify expected tables exist
			for _, expectedTable := range tt.expectedTables {
				assert.Contains(t, tables, expectedTable,
					"table %s should exist after migration", expectedTable)
			}
		})
	}
}
