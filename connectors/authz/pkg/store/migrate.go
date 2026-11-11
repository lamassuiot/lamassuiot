package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/*.sql oracle_migrations/*.sql
var embedMigrations embed.FS

var schemaNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// RunMigrations applies all pending goose migrations against the authz database.
// Must be called before any store is created. Idempotent — safe on every startup.
func RunMigrations(db *sql.DB, schema string, logger *logrus.Entry) error {
	return RunMigrationCommand(context.Background(), db, schema, "up", nil, logger)
}

// RunMigrationsForProvider applies the migration set for the selected Authz
// persistence provider. An omitted provider retains PostgreSQL compatibility.
func RunMigrationsForProvider(db *sql.DB, schema, provider string, logger *logrus.Entry) error {
	return RunMigrationCommandForProvider(context.Background(), db, schema, "up", nil, provider, logger)
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
	return RunMigrationCommandForProvider(ctx, db, schema, command, args, "postgres", logger)
}

// RunMigrationCommandForProvider runs a Goose command using provider-specific
// migrations and version tracking.
func RunMigrationCommandForProvider(ctx context.Context, db *sql.DB, schema, command string, args []string, provider string, logger *logrus.Entry) error {
	provider = normalizeProvider(provider)
	if provider != "postgres" && provider != "oracle" {
		return fmt.Errorf("unsupported Authz migration provider %q (supported: postgres, oracle)", provider)
	}
	if provider != "oracle" {
		if err := ensureSchema(ctx, db, schema, logger); err != nil {
			return err
		}
	} else if schema != "" {
		return fmt.Errorf("Oracle Authz migrations run in the connected user's schema; schema must be empty")
	}

	gooseProvider, err := newProvider(db, provider)
	if err != nil {
		return err
	}

	switch command {
	case "up":
		results, err := gooseProvider.Up(ctx)
		logResults(results, logger)
		return err

	case "up-to":
		version, err := versionArg(args)
		if err != nil {
			return err
		}
		results, err := gooseProvider.UpTo(ctx, version)
		logResults(results, logger)
		return err

	case "down":
		result, err := gooseProvider.Down(ctx)
		if result != nil {
			logResults([]*goose.MigrationResult{result}, logger)
		}
		return err

	case "status":
		statuses, err := gooseProvider.Status(ctx)
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
		version, err := gooseProvider.GetDBVersion(ctx)
		if err != nil {
			return fmt.Errorf("read database version: %w", err)
		}
		logger.Infof("current database version: %d", version)
		return nil

	default:
		return fmt.Errorf("unknown migration command %q (supported: up, up-to, down, status, version)", command)
	}
}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "postgres", "postgresql":
		return "postgres"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
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

func newProvider(db *sql.DB, provider string) (*goose.Provider, error) {
	migrationDir := "migrations"
	if provider == "oracle" {
		migrationDir = "oracle_migrations"
	}
	sub, err := fs.Sub(embedMigrations, migrationDir)
	if err != nil {
		return nil, fmt.Errorf("prepare embedded migrations: %w", err)
	}
	if provider == "oracle" {
		gooseProvider, err := goose.NewProvider(goose.DialectCustom, db, sub,
			goose.WithStore(newOracleMigrationStore()), goose.WithIsolateDDL(true))
		if err != nil {
			return nil, fmt.Errorf("create Oracle goose provider: %w", err)
		}
		return gooseProvider, nil
	}
	gooseProvider, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		return nil, fmt.Errorf("create goose provider: %w", err)
	}
	return gooseProvider, nil
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
