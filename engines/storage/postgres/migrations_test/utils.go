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

func RunDB(t *testing.T, logger *logrus.Entry, dbName string) (func() error, *gorm.DB) {
	cleanup, cfg, err := postgres_test.RunPostgresDocker(map[string]string{
		dbName: "",
	})
	if err != nil {
		t.Fatalf("could not launch Postgres: %s", err)
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, dbName, cfg.Port)
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
			logger.Infof("APPLYING MIGRATION %s: %d", s.Path, s.Version)
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
	var tables []string
	if err := con.Table("information_schema.tables").Where("table_schema = ?", "public").Pluck("table_name", &tables).Error; err != nil {
		t.Fatalf("could not get tables: %s", err)
	}

	// Truncate all tables but not the migrations table
	tables = slices.DeleteFunc(tables, func(s string) bool {
		return s == "goose_db_version"
	})

	tx := con.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE;", strings.Join(tables, ", ")))
	err := tx.Error
	if err != nil {
		t.Fatalf("could not truncate tables: %s", err)
	}
}
