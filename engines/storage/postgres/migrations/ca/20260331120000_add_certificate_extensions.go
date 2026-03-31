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

	rows, err := tx.QueryContext(ctx, "SELECT serial_number, certificate FROM certificates")
	if err != nil {
		return err
	}
	defer rows.Close()

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, row := range result {
		serialNumber, ok := row["serial_number"].(string)
		if !ok || serialNumber == "" {
			return fmt.Errorf("invalid serial number while backfilling certificate extensions")
		}

		base64Certificate, ok := row["certificate"].(string)
		if !ok || base64Certificate == "" {
			continue
		}

		certificate, err := mhelper.DecodeCertificate(base64Certificate)
		if err != nil {
			return fmt.Errorf("decode certificate %s: %w", serialNumber, err)
		}

		keyUsageJSON, err := json.Marshal(models.X509KeyUsage(certificate.KeyUsage))
		if err != nil {
			return fmt.Errorf("marshal key usage for certificate %s: %w", serialNumber, err)
		}

		extendedKeyUsage := make([]models.X509ExtKeyUsage, 0, len(certificate.ExtKeyUsage))
		for _, usage := range certificate.ExtKeyUsage {
			extendedKeyUsage = append(extendedKeyUsage, models.X509ExtKeyUsage(usage))
		}

		extendedKeyUsageJSON, err := json.Marshal(extendedKeyUsage)
		if err != nil {
			return fmt.Errorf("marshal extended key usage for certificate %s: %w", serialNumber, err)
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE certificates
			SET
				extensions_key_usage = $1::jsonb,
				extensions_extended_key_usage = $2::jsonb
			WHERE serial_number = $3
		`, string(keyUsageJSON), string(extendedKeyUsageJSON), serialNumber); err != nil {
			return fmt.Errorf("update certificate %s extensions: %w", serialNumber, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE certificates
		SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
			$1::text,
			'[]'::jsonb
		)
	`, models.CertificateMetadataLinksKey); err != nil {
		return err
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

	if _, err := tx.ExecContext(ctx, `
		UPDATE certificates
		SET metadata = COALESCE(metadata, '{}'::jsonb) - $1
	`, models.CertificateMetadataLinksKey); err != nil {
		return err
	}

	return nil
}
