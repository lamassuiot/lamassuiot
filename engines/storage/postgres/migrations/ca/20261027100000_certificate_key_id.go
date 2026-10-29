package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

const certificateKeyIDBackfillBatchSize = 500

func Register20261027100000CertificateKeyID() {
	goose.AddMigrationContext(upCertificateKeyID, downCertificateKeyID)
}

// upCertificateKeyID adds the ID of each certificate's key in the KMS. With engine_id it identifies
// the key, so the certificate no longer depends on its SKI to find it.
func upCertificateKeyID(ctx context.Context, tx *sql.Tx) error {
	queries := []string{
		"ALTER TABLE certificates ADD COLUMN key_id TEXT NOT NULL DEFAULT '';",
		"CREATE INDEX certificates_key_idx ON certificates (engine_id, key_id) WHERE engine_id <> '';",
	}

	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	return backfillCertificateKeyIDs(ctx, tx)
}

// backfillCertificateKeyIDs fills key_id for the certificates whose key the KMS holds (those with an
// engine_id). Every crypto engine names a key after the SHA-256 of its SubjectPublicKeyInfo.
// Unreadable certificates are skipped: they keep an empty key_id and the migration goes on.
func backfillCertificateKeyIDs(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "CA", "Migrations")

	lastSerialNumber := ""
	for {
		rows, err := tx.QueryContext(ctx, `
			SELECT serial_number, certificate
			FROM certificates
			WHERE engine_id <> '' AND serial_number > $1
			ORDER BY serial_number
			LIMIT $2
		`, lastSerialNumber, certificateKeyIDBackfillBatchSize)
		if err != nil {
			return err
		}

		type row struct {
			serialNumber string
			certificate  sql.NullString
		}
		batch := make([]row, 0, certificateKeyIDBackfillBatchSize)
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.serialNumber, &r.certificate); err != nil {
				rows.Close()
				return fmt.Errorf("scan certificate key ID backfill row: %w", err)
			}
			batch = append(batch, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate certificate key ID backfill rows: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close certificate key ID backfill rows: %w", err)
		}
		if len(batch) == 0 {
			return nil
		}

		for _, r := range batch {
			lastSerialNumber = r.serialNumber

			certificate, err := mhelper.DecodeCertificate(r.certificate.String)
			if err != nil {
				logger.Warnf("skipping certificate %s: could not decode it: %s", r.serialNumber, err)
				continue
			}
			spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
			if err != nil {
				logger.Warnf("skipping certificate %s: unsupported public key: %s", r.serialNumber, err)
				continue
			}
			digest := sha256.Sum256(spki)

			if _, err := tx.ExecContext(ctx, `UPDATE certificates SET key_id = $1 WHERE serial_number = $2`,
				hex.EncodeToString(digest[:]), r.serialNumber); err != nil {
				return fmt.Errorf("update certificate %s key ID: %w", r.serialNumber, err)
			}
		}
	}
}

func downCertificateKeyID(ctx context.Context, tx *sql.Tx) error {
	queries := []string{
		"DROP INDEX IF EXISTS certificates_key_idx;",
		"ALTER TABLE certificates DROP COLUMN key_id;",
	}

	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	return nil
}
