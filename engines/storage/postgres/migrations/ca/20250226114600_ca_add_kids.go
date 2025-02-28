package ca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register_20250226114600_ca_add_kids() {
	goose.AddMigrationContext(upCaAddKids, downCaAddKids)
}

func getFirstElementOrEmpty(strSlice []string) string {
	if len(strSlice) > 0 {
		return strSlice[0]
	}
	return ""
}

func upCaAddKids(ctx context.Context, tx *sql.Tx) error {
	// List of SQL queries to modify the table
	queries := []string{
		"ALTER TABLE certificates RENAME COLUMN key_id TO subject_key_id;",
		"ALTER TABLE certificates ADD COLUMN authority_key_id VARCHAR;",
		"ALTER TABLE certificates ADD COLUMN issuer_common_name VARCHAR;",
		"ALTER TABLE certificates ADD COLUMN issuer_organization VARCHAR;",
		"ALTER TABLE certificates ADD COLUMN issuer_organization_unit VARCHAR;",
		"ALTER TABLE certificates ADD COLUMN issuer_country VARCHAR;",
		"ALTER TABLE certificates ADD COLUMN issuer_state VARCHAR;",
		"ALTER TABLE certificates ADD COLUMN issuer_locality VARCHAR;",
	}

	// Execute each query in the transaction
	for _, query := range queries {
		_, err := tx.Exec(query)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	rows, err := tx.QueryContext(ctx, "SELECT serial_number, certificate FROM certificates")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	// Process each certificate
	for _, r := range result {
		base64Cert := r["certificate"].(string)

		// Decode PEM certificate
		decodedPEM, err := base64.StdEncoding.DecodeString(base64Cert)
		if err != nil {
			return err
		}

		certBlock, _ := pem.Decode(decodedPEM)
		if certBlock != nil {
			// Parse the certificate and update the database
			certificate, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				return err
			}

			_, err = tx.ExecContext(ctx, `
				UPDATE certificates 
				SET 
					authority_key_id = $1,
					issuer_common_name = $2,
					issuer_organization = $3,
					issuer_organization_unit = $4,
					issuer_country = $5,
					issuer_state = $6,
					issuer_locality = $7
				WHERE serial_number = $8
			`,
				helpers.FormatHexWithColons(certificate.AuthorityKeyId),
				certificate.Issuer.CommonName,
				getFirstElementOrEmpty(certificate.Issuer.Organization),
				getFirstElementOrEmpty(certificate.Issuer.OrganizationalUnit),
				getFirstElementOrEmpty(certificate.Issuer.Country),
				getFirstElementOrEmpty(certificate.Issuer.Province),
				getFirstElementOrEmpty(certificate.Issuer.Locality),
				r["serial_number"],
			)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func downCaAddKids(ctx context.Context, tx *sql.Tx) error {
	// List of SQL queries to undo the previous changes
	queries := []string{
		"ALTER TABLE certificates RENAME COLUMN subject_key_id TO key_id;",
		"ALTER TABLE certificates DROP COLUMN authority_key_id;",
		"ALTER TABLE certificates DROP COLUMN issuer_common_name;",
		"ALTER TABLE certificates DROP COLUMN issuer_organization;",
		"ALTER TABLE certificates DROP COLUMN issuer_organization_unit;",
		"ALTER TABLE certificates DROP COLUMN issuer_country;",
		"ALTER TABLE certificates DROP COLUMN issuer_state;",
		"ALTER TABLE certificates DROP COLUMN issuer_locality;",
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
