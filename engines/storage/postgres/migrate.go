package postgres

import (
	"context"
	"fmt"

	lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	log "github.com/sirupsen/logrus"
)

// MigrateSchema applies all pending migrations for the specified schema
func MigrateSchema(logger *log.Entry, config lconfig.PostgresPSEConfig, schema string) error {
	logger.Infof("Starting migration for schema: %s", schema)

	psqlCli, err := CreatePostgresDBConnection(logger, config, schema)
	if err != nil {
		return fmt.Errorf("could not create postgres connection: %w", err)
	}

	// Ensure schema exists
	psqlCli.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema))

	// Set search_path for migrations
	psqlCli.Exec(fmt.Sprintf("SET search_path TO %s", schema))

	m := NewMigrator(logger, psqlCli)

	// Get current and target versions
	c, t, err := m.Goose.GetVersions(context.Background())
	if err != nil {
		return fmt.Errorf("could not get db version: %w", err)
	}

	logger.Infof("Current version: %d", c)
	logger.Infof("Target version: %d", t)

	if c == t {
		logger.Infof("Schema is already up to date")
		return nil
	}

	// Apply migrations
	m.MigrateToLatest()

	logger.Infof("Successfully migrated schema: %s", schema)
	return nil
}

// MigrateDatabase is deprecated, use MigrateSchema instead
func MigrateDatabase(logger *log.Entry, config lconfig.PostgresPSEConfig, database string) error {
	return MigrateSchema(logger, config, database)
}

// MigrateAllSchemas applies all pending migrations for all Lamassu schemas in the pki database
func MigrateAllSchemas(logger *log.Entry, config lconfig.PostgresPSEConfig) error {
	schemas := []string{
		"ca",
		"devicemanager",
		"dmsmanager",
		"alerts",
		"va",
		"kms",
	}

	logger.Infof("Starting migration for all schemas in pki database")

	for _, schema := range schemas {
		schemaLogger := logger.WithField("schema", schema)
		if err := MigrateSchema(schemaLogger, config, schema); err != nil {
			return fmt.Errorf("failed to migrate schema %s: %w", schema, err)
		}
	}

	logger.Infof("Successfully migrated all schemas")
	return nil
}

// MigrateAllDatabases is deprecated, use MigrateAllSchemas instead
func MigrateAllDatabases(logger *log.Entry, config lconfig.PostgresPSEConfig) error {
	return MigrateAllSchemas(logger, config)
}

// GetSchemaVersion returns the current and target version of the specified schema
func GetSchemaVersion(logger *log.Entry, config lconfig.PostgresPSEConfig, schema string) (current int64, target int64, err error) {
	psqlCli, err := CreatePostgresDBConnection(logger, config, schema)
	if err != nil {
		return 0, 0, fmt.Errorf("could not create postgres connection: %w", err)
	}

	m := NewMigrator(logger, psqlCli)

	current, target, err = m.Goose.GetVersions(context.Background())
	if err != nil {
		return 0, 0, fmt.Errorf("could not get db version: %w", err)
	}

	return current, target, nil
}

// GetDatabaseVersion is deprecated, use GetSchemaVersion instead
func GetDatabaseVersion(logger *log.Entry, config lconfig.PostgresPSEConfig, database string) (current int64, target int64, err error) {
	return GetSchemaVersion(logger, config, database)
}
