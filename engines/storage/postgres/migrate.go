package postgres

import (
	"context"
	"fmt"

	lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	log "github.com/sirupsen/logrus"
)

// MigrateDatabase applies all pending migrations for the specified database
func MigrateDatabase(logger *log.Entry, config lconfig.PostgresPSEConfig, database string) error {
	logger.Infof("Starting migration for database: %s", database)

	psqlCli, err := CreatePostgresDBConnection(logger, config, database)
	if err != nil {
		return fmt.Errorf("could not create postgres connection: %w", err)
	}

	m := NewMigrator(logger, psqlCli)

	// Get current and target versions
	c, t, err := m.Goose.GetVersions(context.Background())
	if err != nil {
		return fmt.Errorf("could not get db version: %w", err)
	}

	logger.Infof("Current version: %d", c)
	logger.Infof("Target version: %d", t)

	if c == t {
		logger.Infof("Database is already up to date")
		return nil
	}

	// Apply migrations
	m.MigrateToLatest()

	logger.Infof("Successfully migrated database: %s", database)
	return nil
}

// MigrateAllDatabases applies all pending migrations for all Lamassu databases
func MigrateAllDatabases(logger *log.Entry, config lconfig.PostgresPSEConfig) error {
	databases := []string{
		CA_DB_NAME,
		DEVICE_DB_NAME,
		DMS_DB_NAME,
		ALERTS_DB_NAME,
		VA_DB_NAME,
		KMS_DB_NAME,
	}

	logger.Infof("Starting migration for all databases")

	for _, db := range databases {
		dbLogger := logger.WithField("database", db)
		if err := MigrateDatabase(dbLogger, config, db); err != nil {
			return fmt.Errorf("failed to migrate database %s: %w", db, err)
		}
	}

	logger.Infof("Successfully migrated all databases")
	return nil
}

// GetDatabaseVersion returns the current and target version of the specified database
func GetDatabaseVersion(logger *log.Entry, config lconfig.PostgresPSEConfig, database string) (current int64, target int64, err error) {
	psqlCli, err := CreatePostgresDBConnection(logger, config, database)
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
