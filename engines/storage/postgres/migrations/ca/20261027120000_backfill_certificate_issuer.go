package ca

import (
	"context"
	"database/sql"
	"fmt"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

const certificateIssuerBackfillBatchSize = 500

func Register20261027120000BackfillCertificateIssuer() {
	goose.AddMigrationContext(upBackfillCertificateIssuer, downBackfillCertificateIssuer)
}

// upBackfillCertificateIssuer fills the issuer columns of the certificates stored without them:
// earlier versions left them empty for the CAs Lamassu created or reissued and for imported
// certificates. Importing a CA finds the CAs it issued by their issuer, so it missed those.
// Unreadable certificates are skipped.
func upBackfillCertificateIssuer(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "CA", "Migrations")

	type row struct {
		serialNumber      string
		base64Certificate string
	}

	updated, skipped := 0, 0
	lastSerialNumber := ""
	for {
		rows, err := tx.QueryContext(ctx, `
			SELECT serial_number, COALESCE(certificate, '')
			FROM certificates
			WHERE serial_number > $1
			  AND COALESCE(issuer_common_name, '') = '' AND COALESCE(issuer_organization, '') = ''
			  AND COALESCE(issuer_organization_unit, '') = '' AND COALESCE(issuer_country, '') = ''
			  AND COALESCE(issuer_state, '') = '' AND COALESCE(issuer_locality, '') = ''
			ORDER BY serial_number
			LIMIT $2
		`, lastSerialNumber, certificateIssuerBackfillBatchSize)
		if err != nil {
			return err
		}

		batch := make([]row, 0, certificateIssuerBackfillBatchSize)
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.serialNumber, &r.base64Certificate); err != nil {
				rows.Close()
				return fmt.Errorf("scan certificate issuer backfill row: %w", err)
			}
			batch = append(batch, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate certificate issuer backfill rows: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close certificate issuer backfill rows: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		for _, r := range batch {
			certificate, err := mhelper.DecodeCertificate(r.base64Certificate)
			if err != nil {
				logger.Warnf("skipping certificate %s: could not decode it: %s", r.serialNumber, err)
				skipped++
				continue
			}

			issuer := chelpers.PkixNameToSubject(certificate.Issuer)
			if _, err := tx.ExecContext(ctx, `
				UPDATE certificates
				SET issuer_common_name = $2, issuer_organization = $3, issuer_organization_unit = $4,
				    issuer_country = $5, issuer_state = $6, issuer_locality = $7
				WHERE serial_number = $1
			`, r.serialNumber, issuer.CommonName, issuer.Organization, issuer.OrganizationUnit, issuer.Country, issuer.State, issuer.Locality); err != nil {
				return fmt.Errorf("update certificate %s issuer: %w", r.serialNumber, err)
			}
			updated++
		}

		lastSerialNumber = batch[len(batch)-1].serialNumber
	}

	logger.Infof("backfilled the issuer of %d certificates, skipped %d", updated, skipped)
	return nil
}

func downBackfillCertificateIssuer(ctx context.Context, tx *sql.Tx) error {
	// The issuer columns now match the certificates: there is nothing to undo.
	return nil
}
