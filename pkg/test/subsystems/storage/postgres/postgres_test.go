package postgres_test

import (
	"fmt"
	"os"
	"slices"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestEmptyDumpImport(t *testing.T) {
	pCleanup, cfg, err := RunPostgresDocker(map[string]string{
		"ca": "",
	})
	if err != nil {
		t.Fatalf("could not launch Postgres: %s", err)
	}

	defer pCleanup()

	// Check CA DB is empty
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, "ca", cfg.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("could not connect to Postgres: %s", err)
	}

	var count int64
	err = db.Table("information_schema.tables").Where("table_schema = ?", "public").Count(&count).Error
	if err != nil {
		t.Fatalf("could not query information_schema.tables: %s", err)
	}

	if count > 0 {
		t.Fatalf("expected no tables, but found %d tables", count)
	}
}

func TestDumpImport(t *testing.T) {
	dump, err := os.ReadFile("test_dump.sql")
	if err != nil {
		t.Fatalf("could not read test_dump.sql: %s", err)
	}

	pCleanup, cfg, err := RunPostgresDocker(map[string]string{
		"ca": string(dump),
	})
	if err != nil {
		t.Fatalf("could not launch Postgres: %s", err)
	}

	defer pCleanup()

	// Check CA DB is empty
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, "ca", cfg.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("could not connect to Postgres: %s", err)
	}

	var count int64
	err = db.Table("information_schema.tables").Where("table_schema = ?", "public").Count(&count).Error
	if err != nil {
		t.Fatalf("could not query information_schema.tables: %s", err)
	}

	if count != 2 {
		t.Fatalf("expected 2 tables, but found %d tables", count)
	}

	var tables []string
	err = db.Table("information_schema.tables").Where("table_schema = ?", "public").Pluck("table_name", &tables).Error
	if err != nil {
		t.Fatalf("could not query information_schema.tables: %s", err)
	}

	expectedTables := []string{"certificates", "ca_certificates"}
	for _, table := range expectedTables {
		if !slices.Contains(tables, table) {
			t.Fatalf("expected table %s not found", table)
		}
	}

	// Check certificates table has row with serial number 5c-d7-2f-8d-e2-a0-37-c4-29-8f-b1-3d-79-f9-18-0d
	var count2 int64
	err = db.Table("certificates").Where("serial_number = ?", "5c-d7-2f-8d-e2-a0-37-c4-29-8f-b1-3d-79-f9-18-0d").Count(&count2).Error
	if err != nil {
		t.Fatalf("could not query certificates: %s", err)
	}

	if count2 != 1 {
		t.Fatalf("expected 1 row in certificates, but found %d rows", count2)
	}
}
