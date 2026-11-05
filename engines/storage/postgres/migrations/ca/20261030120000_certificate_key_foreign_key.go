package ca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

const certificateKeyRelinkBatchSize = 500

func Register20261030120000CertificateKeyForeignKey() {
	goose.AddMigrationContext(upCertificateKeyForeignKey, downCertificateKeyForeignKey)
}

// validateCertificateKeyReferences diagnoses orphan references before installing the FK.
func validateCertificateKeyReferences(ctx context.Context, tx *sql.Tx) error {
	var serial, engineID, keyID string
	err := tx.QueryRowContext(ctx, `SELECT c.serial_number, COALESCE(c.engine_id, ''), c.key_id
  FROM certificates c LEFT JOIN kms.kms_keys k ON k.engine_id = c.engine_id AND k.key_id = c.key_id
  WHERE c.key_id IS NOT NULL AND k.key_id IS NULL ORDER BY c.serial_number LIMIT 1`).Scan(&serial, &engineID, &keyID)
	if err == nil {
		return fmt.Errorf("unresolved certificate key: certificate %s references engine %s key %s; register or repair the key before migrating", serial, engineID, keyID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// MATCH SIMPLE alone accepts a partial NULL reference; a non-null key must identify its engine.
	_, err = tx.ExecContext(ctx, `DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'certificates'::regclass AND conname = 'certificates_key_engine_required') THEN
   ALTER TABLE certificates ADD CONSTRAINT certificates_key_engine_required
    CHECK (key_id IS NULL OR (engine_id IS NOT NULL AND engine_id <> ''));
  END IF;
 END $$;`)
	return err
}

// upCertificateKeyForeignKey makes the (engine_id, key_id) of a certificate a reference to its key in the
// KMS, so that the KMS cannot delete a key a certificate still uses. A certificate whose key the KMS does
// not hold has no reference: a NULL key_id, which a foreign key does not check, replaces the empty string.
// engine_id keeps its values, so the filters on it behave as before.
//
// Existing references are validated too: register legacy keys in the KMS before migrating.
// Missing keys abort the migration without erasing certificate references.
//
// The kms schema must be migrated first: the constraint refers to its kms_keys table.
func upCertificateKeyForeignKey(ctx context.Context, tx *sql.Tx) error {
	var hasKMS bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('kms.kms_keys') IS NOT NULL`).Scan(&hasKMS); err != nil {
		return err
	}
	if !hasKMS {
		return errors.New("kms schema not found: migrate the kms schema before the ca schema")
	}

	for _, query := range []string{
		"ALTER TABLE certificates ALTER COLUMN key_id DROP NOT NULL;",
		"ALTER TABLE certificates ALTER COLUMN key_id DROP DEFAULT;",
		"UPDATE certificates SET key_id = NULL WHERE key_id = '';",
		"DROP INDEX IF EXISTS certificates_key_idx;",
		"CREATE INDEX certificates_key_idx ON certificates (engine_id, key_id) WHERE key_id IS NOT NULL;",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	if err := relinkCertificateKeys(ctx, tx); err != nil {
		return err
	}

	if err := validateCertificateKeyReferences(ctx, tx); err != nil {
		return err
	}

	// An installation which applied a hand-run NOT VALID variant of this migration already holds the
	// constraint: validating it here is all that remains.
	if _, err := tx.ExecContext(ctx, `
		ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_key_fk;
		ALTER TABLE certificates ADD CONSTRAINT certificates_key_fk
			FOREIGN KEY (engine_id, key_id) REFERENCES kms.kms_keys (engine_id, key_id)
			ON DELETE RESTRICT ON UPDATE CASCADE;`); err != nil {
		return err
	}

	return nil
}

// relinkCertificateKeys points the certificates whose key_id names no key of their engine at the key the
// engine does hold with their public key. Keys of CAs imported before the KMS are registered under their
// SKI, not under the digest of their public key that key_id holds. Unreadable certificates are skipped.
func relinkCertificateKeys(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "CA", "Migrations")

	type candidate struct {
		serialNumber, engineID string
		certificate            sql.NullString
	}

	relinked := 0
	lastSerialNumber := ""
	for {
		rows, err := tx.QueryContext(ctx, `
			SELECT c.serial_number, COALESCE(c.engine_id, ''), c.certificate
			FROM certificates AS c
			WHERE c.key_id IS NOT NULL AND c.serial_number > $1
			  AND NOT EXISTS (SELECT 1 FROM kms.kms_keys AS k WHERE k.engine_id = c.engine_id AND k.key_id = c.key_id)
			ORDER BY c.serial_number
			LIMIT $2`, lastSerialNumber, certificateKeyRelinkBatchSize)
		if err != nil {
			return err
		}

		batch := make([]candidate, 0, certificateKeyRelinkBatchSize)
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.serialNumber, &c.engineID, &c.certificate); err != nil {
				rows.Close()
				return fmt.Errorf("scan certificate key relink row: %w", err)
			}
			batch = append(batch, c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate certificate key relink rows: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close certificate key relink rows: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		for _, c := range batch {
			lastSerialNumber = c.serialNumber

			certificate, err := mhelper.DecodeCertificate(c.certificate.String)
			if err != nil {
				logger.Warnf("skipping certificate %s: could not decode it: %s", c.serialNumber, err)
				continue
			}
			spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
			if err != nil {
				logger.Warnf("skipping certificate %s: unsupported public key: %s", c.serialNumber, err)
				continue
			}
			// the KMS stores public keys as the base64 of their PEM encoding
			publicKey := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

			res, err := tx.ExecContext(ctx, `
				UPDATE certificates AS c SET key_id = k.key_id
				FROM (SELECT key_id FROM kms.kms_keys WHERE engine_id = $1 AND public_key = $2 ORDER BY key_id LIMIT 1) AS k
				WHERE c.serial_number = $3`, c.engineID, publicKey, c.serialNumber)
			if err != nil {
				return fmt.Errorf("relink certificate %s to its key: %w", c.serialNumber, err)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				relinked++
			}
		}
	}

	logger.Infof("pointed %d certificates at the KMS key holding their public key", relinked)
	return nil
}

func downCertificateKeyForeignKey(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		"ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_key_fk;",
		"ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_key_engine_required;",
		"DROP INDEX IF EXISTS certificates_key_idx;",
		"UPDATE certificates SET key_id = '' WHERE key_id IS NULL;",
		"ALTER TABLE certificates ALTER COLUMN key_id SET DEFAULT '';",
		"ALTER TABLE certificates ALTER COLUMN key_id SET NOT NULL;",
		"CREATE INDEX certificates_key_idx ON certificates (engine_id, key_id) WHERE engine_id <> '';",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	return nil
}
