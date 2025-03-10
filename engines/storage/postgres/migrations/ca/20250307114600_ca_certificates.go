package ca

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func Register20250307114600CaCertificates() {
	goose.AddMigrationContext(upCaCertificates, downCaCertificates)
}

func upCaCertificates(ctx context.Context, tx *sql.Tx) error {
	// List of SQL queries to modify the table
	queries := []string{
		"ALTER TABLE certificates ADD COLUMN level int8 NULL;",
	}

	// Execute each query in the transaction
	for _, query := range queries {
		_, err := tx.Exec(query)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return nil
}

func downCaCertificates(ctx context.Context, tx *sql.Tx) error {
	// List of SQL queries to undo the previous changes
	queries := []string{
		"ALTER TABLE certificates DROP COLUMN level;",
	}

	// Execute each query in the transaction
	for _, query := range queries {
		_, err := tx.Exec(query)
		if err != nil {
			// Rollback the transaction if an error occurs
			tx.Rollback()
			return err
		}
	}
	return nil
}
