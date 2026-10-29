package kms

import (
	"context"
	"database/sql"
	"errors"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/pressly/goose/v3"
)

func Register20261027110200BackfillCertificateKeyBindings() {
	goose.AddMigrationContext(upBackfillCertificateKeyBindings, downBackfillCertificateKeyBindings)
}

// upBackfillCertificateKeyBindings makes the certificate bindings match the certificates that use each
// key: the certificates of each CA, its current one and the ones it reissued (deleted CAs leave their
// certificates behind), and every other certificate whose key the KMS holds, whatever its status.
// Earlier versions only bound some of them, in the key metadata, and never unbound them. The CA schema
// must be migrated first so that its certificates record their key_id.
//
// Certificates are bound by the (key_id, engine_id) the CA records. A binding whose certificate still
// exists with an unknown key_id (its certificate could not be read when key_id was backfilled) is
// kept: the key may still be in use.
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

	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE desired_certificate_bindings (key_id text, engine_id text, resource_id text) ON COMMIT DROP`); err != nil {
		return err
	}

	// The certificates of each CA: its current one and, following the reissued-from links back, the
	// ones it reissued with the same key. Like the CA when it deletes a CA, it only follows a link the
	// previous certificate returns with reissued-as: the links are metadata users can edit.
	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE ca_certificate_history ON COMMIT DROP AS
		WITH RECURSIVE history (serial_number, key_id, engine_id, previous) AS (
			SELECT c.serial_number, c.key_id, c.engine_id, c.metadata ->> $1
			FROM ca.ca_certificates AS ca
			JOIN ca.certificates AS c ON c.serial_number = ca.serial_number
			UNION
			SELECT p.serial_number, p.key_id, p.engine_id, p.metadata ->> $1
			FROM history AS h
			JOIN ca.certificates AS p ON p.serial_number = h.previous AND p.key_id = h.key_id AND p.engine_id = h.engine_id
			WHERE p.metadata ->> $2 = h.serial_number
		)
		SELECT DISTINCT serial_number FROM history`, models.CAMetadataReissuedFromKey, models.CAMetadataReissuedAsKey); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO desired_certificate_bindings (key_id, engine_id, resource_id)
		SELECT c.key_id, c.engine_id, c.serial_number
		FROM ca.certificates AS c
		JOIN kms_keys AS k ON k.key_id = c.key_id AND k.engine_id = c.engine_id
		WHERE c.key_id <> '' AND c.engine_id <> ''
		  AND (c.is_ca = false OR EXISTS (SELECT 1 FROM ca_certificate_history AS h WHERE h.serial_number = c.serial_number))`); err != nil {
		return err
	}

	removed, err := tx.ExecContext(ctx, `
		DELETE FROM key_bindings AS b
		WHERE b.resource_type = 'certificate'
		  AND NOT EXISTS (SELECT 1 FROM desired_certificate_bindings AS d
		                  WHERE d.key_id = b.key_id AND d.engine_id = b.engine_id AND d.resource_id = b.resource_id)
		  AND NOT EXISTS (SELECT 1 FROM ca.certificates AS c WHERE c.serial_number = b.resource_id AND c.key_id = '')`)
	if err != nil {
		return err
	}

	added, err := tx.ExecContext(ctx, `
		INSERT INTO key_bindings (key_id, engine_id, resource_type, resource_id)
		SELECT key_id, engine_id, 'certificate', resource_id FROM desired_certificate_bindings
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
