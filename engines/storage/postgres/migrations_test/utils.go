package migrationstest

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	postgres_test "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	postgresDriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func RunDB(t *testing.T, logger *logrus.Entry, schemaName string) (func() error, *gorm.DB) {
	cleanup, cfg, err := postgres_test.RunPostgresDocker(map[string]string{
		schemaName: "",
	}, false)
	if err != nil {
		t.Fatalf("could not launch Postgres: %s", err)
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d search_path=%s sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, "pki", cfg.Port, schemaName)
	con, err := gorm.Open(postgresDriver.New(
		postgresDriver.Config{
			DSN:                  dsn,
			PreferSimpleProtocol: true,
		},
	), &gorm.Config{
		Logger: postgres.NewGormLogger(logger),
	})
	if err != nil {
		t.Fatalf("could not connect to Postgres: %s", err)
	}

	// Ensure schema exists and set search_path
	con.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName))
	con.Exec(fmt.Sprintf("SET search_path TO %s", schemaName))

	return cleanup, con
}

func assertEqualD(t *testing.T, expected, actual time.Time) {
	if !expected.Equal(actual) {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func ApplyMigration(t *testing.T, logger *logrus.Entry, con *gorm.DB, dbName string) {
	pc, _, _, ok := runtime.Caller(1) // 1 indicates the caller of this function
	if !ok {
		fmt.Println("Unable to get caller information")
		return
	}

	callerFunc := runtime.FuncForPC(pc)
	fmt.Println("Caller Function:", callerFunc.Name())

	regex := regexp.MustCompile(`_([0-9]+_[a-zA-Z0-9_]+)`)

	var migrationName string
	matches := regex.FindStringSubmatch(callerFunc.Name())
	if len(matches) > 1 {
		fmt.Println("Migration version:", matches[1])
		migrationName = matches[1]
	} else {
		t.Fatalf("could not find migration version")
	}

	m := postgres.NewMigrator(logger, con)
	src := m.Goose.ListSources()

	applied := false
	for _, s := range src {
		if strings.Contains(s.Path, migrationName) {
			logger.Infof("APPLYING MIGRATION %s - %d", s.Path, s.Version)
			_, err := m.Goose.ApplyVersion(context.Background(), s.Version, true)
			if err != nil {
				t.Fatalf("could not apply migration: %s", err)
			}

			applied = true
		}
	}

	if !applied {
		t.Fatalf("could not find migration")
	}
}

// RollbackMigration runs the down step of the given migration (e.g. "20261022120000_reenroll_validation_cas").
func RollbackMigration(t *testing.T, logger *logrus.Entry, con *gorm.DB, dbName string, migrationName string) {
	m := postgres.NewMigrator(logger, con)
	for _, s := range m.Goose.ListSources() {
		if strings.Contains(s.Path, migrationName) {
			logger.Infof("ROLLING BACK MIGRATION %s - %d", s.Path, s.Version)
			if _, err := m.Goose.ApplyVersion(context.Background(), s.Version, false); err != nil {
				t.Fatalf("could not roll back migration: %s", err)
			}
			return
		}
	}

	t.Fatalf("could not find migration %s", migrationName)
}

func CleanAllTables(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Get current schema from search_path
	var schemaName string
	con.Raw("SELECT current_schema()").Scan(&schemaName)

	var tables []string
	if err := con.Raw("SELECT tablename FROM pg_tables WHERE schemaname = ?", schemaName).Pluck("tablename", &tables).Error; err != nil {
		t.Fatalf("could not get tables: %s", err)
	}

	// Truncate all tables but not the migrations table
	tables = slices.DeleteFunc(tables, func(s string) bool {
		return s == "goose_db_version"
	})

	if len(tables) > 0 {
		// Qualify table names with schema
		qualifiedTables := make([]string, len(tables))
		for i, table := range tables {
			qualifiedTables[i] = fmt.Sprintf("%s.%s", schemaName, table)
		}

		tx := con.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE;", strings.Join(qualifiedTables, ", ")))
		err := tx.Error
		if err != nil {
			t.Fatalf("could not truncate tables: %s", err)
		}
	}
}

func assertTenantRLSEnabled(t *testing.T, con *gorm.DB, schema string, table string, policy string) {
	t.Helper()

	var isSuperuser, bypassRLS bool
	if err := con.Raw("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'lamassu_app'").Row().Scan(&isSuperuser, &bypassRLS); err != nil {
		t.Fatalf("could not read lamassu_app role: %s", err)
	}
	assert.False(t, isSuperuser, "lamassu_app must not be a superuser")
	assert.False(t, bypassRLS, "lamassu_app must not bypass RLS")

	assert.True(t, hasSchemaUsage(t, con, schema), "lamassu_app must have USAGE on schema %s", schema)
	for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		assert.True(t, hasTablePrivilege(t, con, schema, table, privilege), "lamassu_app must have %s on %s.%s", privilege, schema, table)
	}

	enabled, forced := tableRLSStatus(t, con, schema, table)
	assert.True(t, enabled, "row level security must be enabled on %s.%s", schema, table)
	assert.False(t, forced, "row level security must not be forced on %s.%s", schema, table)

	var roles, command string
	if err := con.Raw("SELECT array_to_string(roles, ','), cmd FROM pg_policies WHERE schemaname = ? AND tablename = ? AND policyname = ?", schema, table, policy).Row().Scan(&roles, &command); err != nil {
		t.Fatalf("could not read policy %s on %s.%s: %s", policy, schema, table, err)
	}
	assert.Equal(t, "lamassu_app", roles, "policy %s must only apply to lamassu_app", policy)
	assert.Equal(t, "ALL", command, "policy %s must apply to every command", policy)
}

func assertTenantRLSDisabled(t *testing.T, con *gorm.DB, schema string, table string, policy string) {
	t.Helper()

	assert.False(t, hasSchemaUsage(t, con, schema), "lamassu_app must not have USAGE on schema %s", schema)
	for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		assert.False(t, hasTablePrivilege(t, con, schema, table, privilege), "lamassu_app must not have %s on %s.%s", privilege, schema, table)
	}

	enabled, _ := tableRLSStatus(t, con, schema, table)
	assert.False(t, enabled, "row level security must be disabled on %s.%s", schema, table)

	var policies int64
	if err := con.Raw("SELECT count(*) FROM pg_policies WHERE schemaname = ? AND tablename = ? AND policyname = ?", schema, table, policy).Row().Scan(&policies); err != nil {
		t.Fatalf("could not count policies on %s.%s: %s", schema, table, err)
	}
	assert.Zero(t, policies, "policy %s must not exist on %s.%s", policy, schema, table)
}

func hasSchemaUsage(t *testing.T, con *gorm.DB, schema string) bool {
	t.Helper()

	var granted bool
	if err := con.Raw("SELECT has_schema_privilege('lamassu_app', ?, 'USAGE')", schema).Row().Scan(&granted); err != nil {
		t.Fatalf("could not check USAGE on schema %s: %s", schema, err)
	}
	return granted
}

func hasTablePrivilege(t *testing.T, con *gorm.DB, schema string, table string, privilege string) bool {
	t.Helper()

	var granted bool
	if err := con.Raw("SELECT has_table_privilege('lamassu_app', ?, ?)", schema+"."+table, privilege).Row().Scan(&granted); err != nil {
		t.Fatalf("could not check %s on %s.%s: %s", privilege, schema, table, err)
	}
	return granted
}

func tableRLSStatus(t *testing.T, con *gorm.DB, schema string, table string) (bool, bool) {
	t.Helper()

	var enabled, forced bool
	if err := con.Raw("SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ? AND c.relname = ?", schema, table).Row().Scan(&enabled, &forced); err != nil {
		t.Fatalf("could not read row level security status of %s.%s: %s", schema, table, err)
	}
	return enabled, forced
}
