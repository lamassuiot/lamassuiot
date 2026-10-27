package kms

import (
	"context"
	"database/sql"
	"errors"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/pressly/goose/v3"
)

func Register20261027110200BackfillCertificateKeyBindings() {
	goose.AddMigrationContext(upBackfillCertificateKeyBindings, downBackfillCertificateKeyBindings)
}

// upBackfillCertificateKeyBindings makes the certificate bindings match the certificates that use each
// key: the current certificate of each CA (reissued and deleted CAs leave their certificates behind)
// and every other certificate whose key the KMS holds, whatever its status. Earlier versions only bound some of them, in the key metadata, and never unbound them. It only
// reads the CA schema, which must be migrated first so that its certificates record their key_id.
//
// A binding whose certificate still exists with an unknown key_id (its certificate could not be read
// when key_id was backfilled) is kept: the key may still be in use.
func upBackfillCertificateKeyBindings(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "KMS", "Migrations")

	var hasCertificates bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('ca.certificates') IS NOT NULL AND to_regclass('ca.ca_certificates') IS NOT NULL`).Scan(&hasCertificates); err != nil {
		return err
	}
	if !hasCertificates {
		logger.Infof("no CA certificates found, no key bindings to backfill")
		return nil
	}

	var hasKeyID bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'ca' AND table_name = 'certificates' AND column_name = 'key_id')`).Scan(&hasKeyID); err != nil {
		return err
	}
	if !hasKeyID {
		return errors.New("ca.certificates has no key_id column: migrate the ca schema first, then the kms schema")
	}

	removed, err := tx.ExecContext(ctx, `
		DELETE FROM key_bindings AS b
		WHERE b.resource_type = 'certificate'
		  AND NOT EXISTS (SELECT 1 FROM (SELECT c.serial_number, c.key_id, c.engine_id
		                  FROM ca.certificates AS c
		                  WHERE c.key_id <> '' AND c.engine_id <> ''
		                    AND (c.is_ca = false OR EXISTS (SELECT 1 FROM ca.ca_certificates AS ca WHERE ca.serial_number = c.serial_number))) AS u
		                  WHERE u.serial_number = b.resource_id AND u.key_id = b.key_id AND u.engine_id = b.engine_id)
		  AND NOT EXISTS (SELECT 1 FROM ca.certificates AS c WHERE c.serial_number = b.resource_id AND c.key_id = '')`)
	if err != nil {
		return err
	}

	added, err := tx.ExecContext(ctx, `
		INSERT INTO key_bindings (key_id, engine_id, resource_type, resource_id)
		SELECT u.key_id, u.engine_id, 'certificate', u.serial_number
		FROM (SELECT c.serial_number, c.key_id, c.engine_id
		      FROM ca.certificates AS c
		      WHERE c.key_id <> '' AND c.engine_id <> ''
		        AND (c.is_ca = false OR EXISTS (SELECT 1 FROM ca.ca_certificates AS ca WHERE ca.serial_number = c.serial_number))) AS u
		JOIN kms_keys AS k ON k.key_id = u.key_id AND k.engine_id = u.engine_id
		ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}

	removedRows, _ := removed.RowsAffected()
	addedRows, _ := added.RowsAffected()
	logger.Infof("backfilled certificate key bindings: %d added, %d removed", addedRows, removedRows)
	return nil
}

func downBackfillCertificateKeyBindings(ctx context.Context, tx *sql.Tx) error {
	// The bindings now match the certificates: there is nothing to undo.
	return nil
}
