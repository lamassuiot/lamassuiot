package sqlite

import (
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/sirupsen/logrus"
)

func TestILIKEReplacement(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	db, err := CreateSQLiteDBConnection(logrus.NewEntry(logger), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to create sqlite connection: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql DB: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	if err := db.Exec("CREATE TABLE test_ilike (name TEXT)").Error; err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	if err := db.Exec("INSERT INTO test_ilike (name) VALUES (?)", "Alice").Error; err != nil {
		t.Fatalf("failed to insert row: %v", err)
	}

	var name string
	// Use FilterOperandToWhereClause which detects SQLite and uses LIKE instead of ILIKE
	tx := db.Table("test_ilike").Select("name")
	tx = postgres.FilterOperandToWhereClause(resources.FilterOption{
		Field:           "name",
		Value:           "alice",
		FilterOperation: resources.StringEqualIgnoreCase,
	}, tx)

	if err := tx.Scan(&name).Error; err != nil {
		t.Fatalf("Filter with case-insensitive equality failed: %v", err)
	}

	if name != "Alice" {
		t.Fatalf("expected to fetch 'Alice', got '%s'", name)
	}
}
