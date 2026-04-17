package ca

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

const certificateExtensionsBackfillBatchSize = 500

type certificateExtensionsBackfillRow struct {
	serialNumber      string
	base64Certificate string
}

func Register20260331120000AddCertificateExtensions() {
	goose.AddMigrationContext(upAddCertificateExtensions, downAddCertificateExtensions)
}

func upAddCertificateExtensions(ctx context.Context, tx *sql.Tx) error {
	queries := []string{
		"ALTER TABLE certificates ADD COLUMN extensions_key_usage JSONB NOT NULL DEFAULT '[]'::jsonb;",
		"ALTER TABLE certificates ADD COLUMN extensions_extended_key_usage JSONB NOT NULL DEFAULT '[]'::jsonb;",
	}

	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	lastSerialNumber := ""
	for {
		rows, err := tx.QueryContext(ctx, `
			SELECT serial_number, certificate
			FROM certificates
			WHERE serial_number > $1
			ORDER BY serial_number
			LIMIT $2
		`, lastSerialNumber, certificateExtensionsBackfillBatchSize)
		if err != nil {
			return err
		}

		batch := make([]certificateExtensionsBackfillRow, 0, certificateExtensionsBackfillBatchSize)
		for rows.Next() {
			var row certificateExtensionsBackfillRow
			if err := rows.Scan(&row.serialNumber, &row.base64Certificate); err != nil {
				rows.Close()
				return fmt.Errorf("scan certificate extensions backfill row: %w", err)
			}

			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate certificate extensions backfill rows: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close certificate extensions backfill rows: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		for _, row := range batch {
			if row.serialNumber == "" {
				return fmt.Errorf("invalid serial number while backfilling certificate extensions")
			}
			if row.base64Certificate == "" {
				continue
			}

			certificate, err := mhelper.DecodeCertificate(row.base64Certificate)
			if err != nil {
				return fmt.Errorf("decode certificate %s: %w", row.serialNumber, err)
			}

			keyUsageJSON, err := json.Marshal(models.X509KeyUsage(certificate.KeyUsage))
			if err != nil {
				return fmt.Errorf("marshal key usage for certificate %s: %w", row.serialNumber, err)
			}

			extendedKeyUsage := make([]models.X509ExtKeyUsage, 0, len(certificate.ExtKeyUsage))
			for _, usage := range certificate.ExtKeyUsage {
				extendedKeyUsage = append(extendedKeyUsage, models.X509ExtKeyUsage(usage))
			}

			extendedKeyUsageJSON, err := json.Marshal(extendedKeyUsage)
			if err != nil {
				return fmt.Errorf("marshal extended key usage for certificate %s: %w", row.serialNumber, err)
			}

			if _, err := tx.ExecContext(ctx, `
				UPDATE certificates
				SET
					extensions_key_usage = $1::jsonb,
					extensions_extended_key_usage = $2::jsonb
				WHERE serial_number = $3
			`, string(keyUsageJSON), string(extendedKeyUsageJSON), row.serialNumber); err != nil {
				return fmt.Errorf("update certificate %s extensions: %w", row.serialNumber, err)
			}
		}

		lastSerialNumber = batch[len(batch)-1].serialNumber
	}

	if _, err := tx.ExecContext(ctx, "ALTER TABLE certificates DROP COLUMN version_schema;"); err != nil {
		return err
	}

	return nil
}

func downAddCertificateExtensions(ctx context.Context, tx *sql.Tx) error {
	queries := []string{
		"ALTER TABLE certificates ADD COLUMN version_schema VARCHAR;",
		"UPDATE certificates SET version_schema = 'unknown' WHERE version_schema IS NULL;",
		"ALTER TABLE certificates DROP COLUMN extensions_extended_key_usage;",
		"ALTER TABLE certificates DROP COLUMN extensions_key_usage;",
	}

	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}

	return nil
}
