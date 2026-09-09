package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"

	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

var schemaNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// RunMigrations applies all pending goose migrations against the authz database.
// Must be called before any store is created. Idempotent — safe on every startup.
func RunMigrations(db *sql.DB, schema string, logger *logrus.Entry) error {
	return RunMigrationCommand(context.Background(), db, schema, "up", nil, logger)
}

// RunMigrationCommand runs a single goose command against the authz database.
// Supported commands: up, up-to <version>, down, status, version.
//
// "down" rolls back a single migration, so what it undoes depends on the current
// version. Rolling back far enough reaches the initial migration, which drops
// principals, principal_policies and policies — the whole authorization model.
// Callers are responsible for confirming it.
//
// When schema is non-empty it is created if missing. goose resolves both its own
// goose_db_version table and the migration DDL through search_path, which the
// connection DSN already carries, so the schema only needs to exist beforehand.
func RunMigrationCommand(ctx context.Context, db *sql.DB, schema, command string, args []string, logger *logrus.Entry) error {
	if err := ensureSchema(ctx, db, schema, logger); err != nil {
		return err
	}

	provider, err := newProvider(db)
	if err != nil {
		return err
	}

	switch command {
	case "up":
		results, err := provider.Up(ctx)
		logResults(results, logger)
		return err

	case "up-to":
		version, err := versionArg(args)
		if err != nil {
			return err
		}
		results, err := provider.UpTo(ctx, version)
		logResults(results, logger)
		return err

	case "down":
		result, err := provider.Down(ctx)
		if result != nil {
			logResults([]*goose.MigrationResult{result}, logger)
		}
		return err

	case "status":
		statuses, err := provider.Status(ctx)
		if err != nil {
			return fmt.Errorf("read migration status: %w", err)
		}
		for _, s := range statuses {
			applied := "-"
			if s.State == goose.StateApplied {
				applied = s.AppliedAt.Format("2006-01-02 15:04:05")
			}
			logger.Infof("%-9s %-20s %s", s.State, applied, s.Source.Path)
		}
		return nil

	case "version":
		version, err := provider.GetDBVersion(ctx)
		if err != nil {
			return fmt.Errorf("read database version: %w", err)
		}
		logger.Infof("current database version: %d", version)
		return nil

	default:
		return fmt.Errorf("unknown migration command %q (supported: up, up-to, down, status, version)", command)
	}
}

// ensureSchemaFunc creates the schema named by its argument. Postgres cannot
// bind an identifier as a query parameter, so a configured schema name would
// otherwise have to be pasted into the statement from Go. This keeps the name a
// bind parameter and lets the server quote it with format(%I), which is correct
// for any identifier; the function body itself is a constant.
const ensureSchemaFunc = `CREATE OR REPLACE FUNCTION pg_temp.lamassu_ensure_schema(schema_name text)
RETURNS void AS $fn$
BEGIN
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', schema_name);
END;
$fn$ LANGUAGE plpgsql;`

func ensureSchema(ctx context.Context, db *sql.DB, schema string, logger *logrus.Entry) error {
	if schema == "" {
		return nil
	}
	if !schemaNamePattern.MatchString(schema) {
		return fmt.Errorf("invalid schema name %q", schema)
	}

	// pg_temp is session scoped, so the helper and the call to it have to run on
	// the same pooled connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, ensureSchemaFunc); err != nil {
		return fmt.Errorf("prepare schema helper: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_temp.lamassu_ensure_schema($1)", schema); err != nil {
		return fmt.Errorf("create schema %s: %w", schema, err)
	}

	logger.Infof("using schema: %s", schema)
	return nil
}

func newProvider(db *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("prepare embedded migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		return nil, fmt.Errorf("create goose provider: %w", err)
	}
	return provider, nil
}

func versionArg(args []string) (int64, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("this command requires a VERSION argument")
	}
	version, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid VERSION %q: %w", args[0], err)
	}
	return version, nil
}

func logResults(results []*goose.MigrationResult, logger *logrus.Entry) {
	for _, r := range results {
		if r.Error != nil {
			logger.WithError(r.Error).Errorf("migration failed: %s", r.Source.Path)
		} else {
			logger.Infof("migration %s: %s (%.2fs)", r.Direction, r.Source.Path, r.Duration.Seconds())
		}
	}
}
