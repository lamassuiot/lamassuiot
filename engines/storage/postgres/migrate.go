package postgres

import (
	"context"
	"fmt"
	"slices"

	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	log "github.com/sirupsen/logrus"
)

// schemaDependencies lists the schemas that have to be migrated before another one: the certificates of
// the CA schema reference the keys of the KMS schema.
var schemaDependencies = map[string][]string{
	CA_SCHEMA: {KMS_SCHEMA},
	VA_SCHEMA: {CA_SCHEMA},
}

// MigrationSchemaOrder returns the Lamassu schemas in the order they are migrated: every schema comes
// after the ones it depends on.
func MigrationSchemaOrder() []string {
	return []string{KMS_SCHEMA, CA_SCHEMA, DEVICE_SCHEMA, DMS_SCHEMA, ALERTS_SCHEMA, VA_SCHEMA}
}

// OrderForMigration returns schemas ordered for migration: the ones in MigrationSchemaOrder in that
// order, then the rest as they came.
func OrderForMigration(schemas []string) []string {
	order := MigrationSchemaOrder()
	rank := func(schema string) int {
		if i := slices.Index(order, schema); i != -1 {
			return i
		}
		return len(order)
	}

	ordered := slices.Clone(schemas)
	slices.SortStableFunc(ordered, func(a, b string) int { return rank(a) - rank(b) })
	return ordered
}

// MigrateSchema applies all pending migrations for the specified schema, after the ones of the schemas
// it depends on
func MigrateSchema(logger *log.Entry, config lconfig.PostgresPSEConfig, schema string) error {
	for _, dependency := range schemaDependencies[schema] {
		if err := MigrateSchema(logger.WithField("schema", dependency), config, dependency); err != nil {
			return fmt.Errorf("failed to migrate schema %s, which %s depends on: %w", dependency, schema, err)
		}
	}

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
	if m == nil {
		return nil
	}

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
	logger.Infof("Starting migration for all schemas in pki database")

	for _, schema := range MigrationSchemaOrder() {
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
