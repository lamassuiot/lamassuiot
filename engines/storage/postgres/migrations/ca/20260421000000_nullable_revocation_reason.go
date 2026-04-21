package ca

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func Register20260421000000NullableRevocationReason() {
	goose.AddMigrationContext(upNullableRevocationReason, downNullableRevocationReason)
}

func upNullableRevocationReason(ctx context.Context, tx *sql.Tx) error {
	// Clear revocation_reason for certificates and CAs that are not revoked.
	// Previously the zero value (0 = "Unspecified") was stored for all rows,
	// making it impossible to distinguish "never revoked" from "revoked with Unspecified reason".
	// After this migration only revoked rows retain their reason; all others are NULL.
	queries := []string{
		`UPDATE certificates SET revocation_reason = NULL WHERE status != 'REVOKED';`,
		`UPDATE ca_certificates SET revocation_reason = NULL WHERE status != 'REVOKED';`,
	}

	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	return nil
}

func downNullableRevocationReason(ctx context.Context, tx *sql.Tx) error {
	// Restore the previous behaviour: set revocation_reason to "Unspecified" (0)
	// for all non-revoked rows that currently have NULL.
	queries := []string{
		`UPDATE certificates SET revocation_reason = 'Unspecified' WHERE revocation_reason IS NULL AND status != 'REVOKED';`,
		`UPDATE ca_certificates SET revocation_reason = 'Unspecified' WHERE revocation_reason IS NULL AND status != 'REVOKED';`,
	}

	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	return nil
}
