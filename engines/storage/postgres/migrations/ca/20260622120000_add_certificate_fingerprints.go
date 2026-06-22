package ca

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"fmt"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/sha3"
)

const fingerprintsBackfillBatchSize = 500

func Register20260622120000AddCertificateFingerprints() {
	goose.AddMigrationContext(upAddCertificateFingerprints, downAddCertificateFingerprints)
}

func upAddCertificateFingerprints(ctx context.Context, tx *sql.Tx) error {
	for _, table := range []string{"ca_certificates", "certificates"} {
		for _, col := range []string{
			"fingerprint_sha1",
			"fingerprint_sha256",
			"fingerprint_sha512",
			"fingerprint_sha3_256",
			"fingerprint_sha3_512",
		} {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(
				"ALTER TABLE %s ADD COLUMN %s TEXT NOT NULL DEFAULT '';", table, col,
			)); err != nil {
				return fmt.Errorf("add column %s.%s: %w", table, col, err)
			}
		}
	}

	// Backfill certificates directly (it holds the certificate column).
	if err := backfillCertificatesFingerprints(ctx, tx); err != nil {
		return fmt.Errorf("backfill certificates: %w", err)
	}

	// ca_certificates has no certificate column — copy fingerprints from certificates via FK.
	if _, err := tx.ExecContext(ctx, `
		UPDATE ca_certificates ca
		SET
			fingerprint_sha1     = c.fingerprint_sha1,
			fingerprint_sha256   = c.fingerprint_sha256,
			fingerprint_sha512   = c.fingerprint_sha512,
			fingerprint_sha3_256 = c.fingerprint_sha3_256,
			fingerprint_sha3_512 = c.fingerprint_sha3_512
		FROM certificates c
		WHERE ca.serial_number = c.serial_number
	`); err != nil {
		return fmt.Errorf("backfill ca_certificates: %w", err)
	}

	return nil
}

func backfillCertificatesFingerprints(ctx context.Context, tx *sql.Tx) error {
	lastSerialNumber := ""
	for {
		rows, err := tx.QueryContext(ctx, `
			SELECT serial_number, certificate
			FROM certificates
			WHERE serial_number > $1
			ORDER BY serial_number
			LIMIT $2
		`, lastSerialNumber, fingerprintsBackfillBatchSize)
		if err != nil {
			return err
		}

		type row struct {
			serialNumber      string
			base64Certificate string
		}

		batch := make([]row, 0, fingerprintsBackfillBatchSize)
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.serialNumber, &r.base64Certificate); err != nil {
				rows.Close()
				return fmt.Errorf("scan row: %w", err)
			}
			batch = append(batch, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate rows: %w", err)
		}
		rows.Close()

		if len(batch) == 0 {
			break
		}

		for _, r := range batch {
			if r.base64Certificate == "" {
				continue
			}

			cert, err := mhelper.DecodeCertificate(r.base64Certificate)
			if err != nil {
				return fmt.Errorf("decode certificate %s: %w", r.serialNumber, err)
			}

			s1 := sha1.Sum(cert.Raw)
			s256 := sha256.Sum256(cert.Raw)
			s512 := sha512.Sum512(cert.Raw)
			var s3256 [32]byte
			sha3.ShakeSum256(s3256[:], cert.Raw)
			s3512 := sha3.Sum512(cert.Raw)

			if _, err := tx.ExecContext(ctx, `
				UPDATE certificates
				SET
					fingerprint_sha1     = $1,
					fingerprint_sha256   = $2,
					fingerprint_sha512   = $3,
					fingerprint_sha3_256 = $4,
					fingerprint_sha3_512 = $5
				WHERE serial_number = $6
			`,
				hex.EncodeToString(s1[:]),
				hex.EncodeToString(s256[:]),
				hex.EncodeToString(s512[:]),
				hex.EncodeToString(s3256[:]),
				hex.EncodeToString(s3512[:]),
				r.serialNumber,
			); err != nil {
				return fmt.Errorf("update certificate %s fingerprints: %w", r.serialNumber, err)
			}
		}

		lastSerialNumber = batch[len(batch)-1].serialNumber
	}

	return nil
}

func downAddCertificateFingerprints(ctx context.Context, tx *sql.Tx) error {
	for _, table := range []string{"ca_certificates", "certificates"} {
		for _, col := range []string{
			"fingerprint_sha1",
			"fingerprint_sha256",
			"fingerprint_sha512",
			"fingerprint_sha3_256",
			"fingerprint_sha3_512",
		} {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(
				"ALTER TABLE %s DROP COLUMN %s;", table, col,
			)); err != nil {
				return fmt.Errorf("drop column %s.%s: %w", table, col, err)
			}
		}
	}

	return nil
}
