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

	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	postgres_test "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/sirupsen/logrus"
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
