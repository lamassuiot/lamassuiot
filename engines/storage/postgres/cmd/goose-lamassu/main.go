// This is custom goose-lamassu binary for Lamassu PostgreSQL databases.
// Based on: https://github.com/pressly/goose/blob/main/examples/go-migrations/main.go

package main

import (
	"context"
	"flag"
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
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=ca port=5432 sslmode=disable" up`)
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=alerts port=5432 sslmode=disable" status`)
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=devicemanager port=5432 sslmode=disable" up-to 5`)
		log.Println()
		log.Println("Valid databases: ca, devicemanager, dmsmanager, alerts, va, kms")
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
	// Example: goose-lamassu "host=localhost user=postgres password=test dbname=ca port=5432 sslmode=disable" up
	dbstring, command := args[0], args[1]

	// Extract database name from connection string
	dbName := extractDBName(dbstring)
	if dbName == "" {
		log.Fatalf("goose-lamassu: could not extract dbname from connection string")
	}

	// Validate database name
	validDatabases := []string{"ca", "devicemanager", "dmsmanager", "alerts", "va", "kms"}
	if !contains(validDatabases, dbName) {
		log.Fatalf("goose-lamassu: invalid database: %s. Must be one of: %s", dbName, strings.Join(validDatabases, ", "))
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

	// Reset global migrations and register migrations for this database
	goose.ResetGlobalMigrations()
	migrations.RegisterGoMigrations(dbName)

	// Get migrations filesystem for this database
	embeddedFS := postgres.GetEmbeddedMigrations()
	migrationsDir := filepath.Join("migrations", dbName)
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

// extractDBName extracts the dbname from a PostgreSQL connection string
func extractDBName(connStr string) string {
	// Parse connection string for dbname parameter
	// Format: "key=value key2=value2 ..."
	parts := strings.Fields(connStr)
	for _, part := range parts {
		if after, ok := strings.CutPrefix(part, "dbname="); ok {
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
