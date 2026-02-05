// This is custom goose-lamassu binary for Lamassu PostgreSQL databases.
// Based on: https://github.com/pressly/goose/blob/main/examples/go-migrations/main.go

package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations"
	"github.com/pressly/goose/v3"
)

var (
	flags = flag.NewFlagSet("goose-lamassu", flag.ExitOnError)
)

func init() {
	flags.Usage = func() {
		log.Println("Usage: goose-lamassu DBSTRING COMMAND [ARGS...]")
		log.Println()
		log.Println("Examples:")
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=pki search_path=ca port=5432 sslmode=disable" up`)
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=pki search_path=alerts port=5432 sslmode=disable" status`)
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=pki search_path=devicemanager port=5432 sslmode=disable" up-to 5`)
		log.Println()
		log.Println("Valid schemas: ca, devicemanager, dmsmanager, alerts, va, kms")
		log.Println()
		log.Println("Commands:")
		log.Println("  up                   Migrate the DB to the most recent version available")
		log.Println("  up-by-one            Migrate the DB up by 1")
		log.Println("  up-to VERSION        Migrate the DB to a specific VERSION")
		log.Println("  down                 Roll back the version by 1")
		log.Println("  down-to VERSION      Roll back to a specific VERSION")
		log.Println("  redo                 Re-run the latest migration")
		log.Println("  reset                Roll back all migrations")
		log.Println("  status               Dump the migration status for the current DB")
		log.Println("  version              Print the current version of the database")
	}
}

func main() {
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("goose-lamassu: failed to parse flags: %v", err)
	}
	args := flags.Args()

	if len(args) < 2 {
		flags.Usage()
		return
	}

	// Parse: goose-lamassu DBSTRING COMMAND [ARGS...]
	// Example: goose-lamassu "host=localhost user=postgres password=test dbname=pki search_path=ca port=5432 sslmode=disable" up
	dbstring, command := args[0], args[1]

	// Extract schema name from connection string
	schemaName := extractSearchPath(dbstring)
	if schemaName == "" {
		log.Fatalf("goose-lamassu: could not extract search_path from connection string. Required format: search_path=<schema>")
	}

	// Validate schema name
	validSchemas := []string{"ca", "devicemanager", "dmsmanager", "alerts", "va", "kms"}
	if !contains(validSchemas, schemaName) {
		log.Fatalf("goose-lamassu: invalid schema: %s. Must be one of: %s", schemaName, strings.Join(validSchemas, ", "))
	}

	// Open database connection
	db, err := goose.OpenDBWithDriver("postgres", dbstring)
	if err != nil {
		log.Fatalf("goose-lamassu: failed to open DB: %v", err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("goose-lamassu: failed to close DB: %v", err)
		}
	}()

	// Ensure schema exists
	if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName)); err != nil {
		log.Fatalf("goose-lamassu: failed to create schema: %v", err)
	}

	// Set search_path for this connection
	if _, err := db.Exec(fmt.Sprintf("SET search_path TO %s", schemaName)); err != nil {
		log.Fatalf("goose-lamassu: failed to set search_path: %v", err)
	}

	// Reset global migrations and register migrations for this schema
	goose.ResetGlobalMigrations()
	migrations.RegisterGoMigrations(schemaName)

	// Get migrations filesystem for this schema
	embeddedFS := postgres.GetEmbeddedMigrations()
	migrationsDir := filepath.Join("migrations", schemaName)
	migrationsFS, err := fs.Sub(embeddedFS, migrationsDir)
	if err != nil {
		log.Fatalf("goose-lamassu: failed to get migrations subdirectory: %v", err)
	}

	// Set the base FS for goose to use
	goose.SetBaseFS(migrationsFS)
	defer goose.SetBaseFS(nil)

	// Prepare command arguments
	arguments := []string{}
	if len(args) > 2 {
		arguments = append(arguments, args[2:]...)
	}

	ctx := context.Background()
	if err := goose.RunContext(ctx, command, db, ".", arguments...); err != nil {
		log.Fatalf("goose-lamassu %v: %v", command, err)
	}
}

// extractSearchPath extracts the search_path from a PostgreSQL connection string
func extractSearchPath(connStr string) string {
	// Parse connection string for search_path parameter
	// Format: "key=value key2=value2 ..."
	parts := strings.Fields(connStr)
	for _, part := range parts {
		if after, ok := strings.CutPrefix(part, "search_path="); ok {
			return after
		}
	}
	return ""
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}
