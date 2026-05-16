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
	// Clear revocation_reason for certificates that are not revoked.
	// Previously the zero value (0 = "Unspecified") was stored for all rows,
	// making it impossible to distinguish "never revoked" from "revoked with Unspecified reason".
	// After this migration only revoked rows retain their reason; all others are NULL.
	// CA certificates are also rows in the certificates table (ca_certificates dropped its own
	// revocation_reason column in 20241223183344_unified_ca_models), so one query covers both.
	_, err := tx.ExecContext(ctx, `UPDATE certificates SET revocation_reason = NULL WHERE status != 'REVOKED';`)
	return err
}

func downNullableRevocationReason(ctx context.Context, tx *sql.Tx) error {
	// Restore the previous behaviour: set revocation_reason to "Unspecified" for all
	// non-revoked rows that currently have NULL.
	_, err := tx.ExecContext(ctx, `UPDATE certificates SET revocation_reason = 'Unspecified' WHERE revocation_reason IS NULL AND status != 'REVOKED';`)
	return err
}
