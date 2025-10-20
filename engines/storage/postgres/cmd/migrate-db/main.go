package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPort     = 5432
	defaultLogLevel = "info"
)

func main() {
	var (
		hostname string
		port     int
		username string
		password string
		database string
		all      bool
		status   bool
		logLevel string
	)

	flag.StringVar(&hostname, "hostname", "", "PostgreSQL hostname (required)")
	flag.IntVar(&port, "port", defaultPort, "PostgreSQL port")
	flag.StringVar(&username, "username", "", "PostgreSQL username (required)")
	flag.StringVar(&password, "password", "", "PostgreSQL password (required)")
	flag.StringVar(&database, "database", "", "Database name to migrate (ca, devicemanager, dmsmanager, alerts, va, kms)")
	flag.BoolVar(&all, "all", false, "Migrate all Lamassu databases")
	flag.BoolVar(&status, "status", false, "Show migration status without applying migrations")
	flag.StringVar(&logLevel, "log-level", defaultLogLevel, "Log level (trace, debug, info, warn, error)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Lamassu PostgreSQL Database Migration Tool\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Migrate a specific database\n")
		fmt.Fprintf(os.Stderr, "  %s -hostname=localhost -username=postgres -password=secret -database=ca\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Migrate all databases\n")
		fmt.Fprintf(os.Stderr, "  %s -hostname=localhost -username=postgres -password=secret -all\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Check migration status\n")
		fmt.Fprintf(os.Stderr, "  %s -hostname=localhost -username=postgres -password=secret -database=ca -status\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Using environment variables\n")
		fmt.Fprintf(os.Stderr, "  POSTGRES_HOSTNAME=localhost POSTGRES_USERNAME=postgres POSTGRES_PASSWORD=secret \\\n")
		fmt.Fprintf(os.Stderr, "  %s -database=ca\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Environment Variables:\n")
		fmt.Fprintf(os.Stderr, "  POSTGRES_HOSTNAME  - PostgreSQL hostname\n")
		fmt.Fprintf(os.Stderr, "  POSTGRES_PORT      - PostgreSQL port\n")
		fmt.Fprintf(os.Stderr, "  POSTGRES_USERNAME  - PostgreSQL username\n")
		fmt.Fprintf(os.Stderr, "  POSTGRES_PASSWORD  - PostgreSQL password\n")
	}

	flag.Parse()

	// Override with environment variables if not set via flags
	if hostname == "" {
		hostname = os.Getenv("POSTGRES_HOSTNAME")
	}
	if username == "" {
		username = os.Getenv("POSTGRES_USERNAME")
	}
	if password == "" {
		password = os.Getenv("POSTGRES_PASSWORD")
	}
	if portEnv := os.Getenv("POSTGRES_PORT"); portEnv != "" && port == defaultPort {
		fmt.Sscanf(portEnv, "%d", &port)
	}

	// Validate required parameters
	if hostname == "" || username == "" || password == "" {
		fmt.Fprintf(os.Stderr, "Error: hostname, username, and password are required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if !all && database == "" {
		fmt.Fprintf(os.Stderr, "Error: either -database or -all flag must be specified\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Validate database name if specified
	if database != "" {
		validDatabases := []string{
			postgres.CA_DB_NAME,
			postgres.DEVICE_DB_NAME,
			postgres.DMS_DB_NAME,
			postgres.ALERTS_DB_NAME,
			postgres.VA_DB_NAME,
			postgres.KMS_DB_NAME,
		}
		valid := slices.Contains(validDatabases, database)
		if !valid {
			fmt.Fprintf(os.Stderr, "Error: invalid database name '%s'. Valid options: %s\n\n",
				database, strings.Join(validDatabases, ", "))
			flag.Usage()
			os.Exit(1)
		}
	}

	// Setup logger
	logger := helpers.SetupLogger(config.LogLevel(logLevel), "PostgreSQL", "Migration")

	// Create configuration
	cfg := lconfig.PostgresPSEConfig{
		Hostname: hostname,
		Port:     port,
		Username: username,
		Password: config.Password(password),
	}

	// Execute migration
	if err := run(logger, cfg, database, all, status); err != nil {
		logger.Fatalf("Migration failed: %v", err)
	}

	logger.Info("Migration completed successfully")
}

func run(logger *log.Entry, cfg lconfig.PostgresPSEConfig, database string, all bool, status bool) error {
	if status {
		return showStatus(logger, cfg, database, all)
	}

	if all {
		return postgres.MigrateAllDatabases(logger, cfg)
	}

	return postgres.MigrateDatabase(logger, cfg, database)
}

func showStatus(logger *log.Entry, cfg lconfig.PostgresPSEConfig, database string, all bool) error {
	databases := []string{database}
	if all {
		databases = []string{
			postgres.CA_DB_NAME,
			postgres.DEVICE_DB_NAME,
			postgres.DMS_DB_NAME,
			postgres.ALERTS_DB_NAME,
			postgres.VA_DB_NAME,
			postgres.KMS_DB_NAME,
		}
	}

	logger.Info("Database Migration Status:")
	logger.Info("==========================")

	for _, db := range databases {
		current, target, err := postgres.GetDatabaseVersion(logger, cfg, db)
		if err != nil {
			return fmt.Errorf("failed to get version for database %s: %w", db, err)
		}

		migrationStatus := "up-to-date"
		if current < target {
			migrationStatus = fmt.Sprintf("pending (%d migrations)", target-current)
		}

		logger.Infof("Database: %-15s | Current: %3d | Target: %3d | Status: %s",
			db, current, target, migrationStatus)
	}

	return nil
}
