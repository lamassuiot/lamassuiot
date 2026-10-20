package ca

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

const certificateIssuerBackfillBatchSize = 500

func Register20261020120000BackfillCertificateIssuer() {
	goose.AddMigrationContext(upBackfillCertificateIssuer, downBackfillCertificateIssuer)
}

// upBackfillCertificateIssuer fills the issuer columns of the certificates stored without them:
// earlier versions left them empty for the CAs Lamassu created or reissued and for imported
// certificates. Importing a CA finds the CAs it issued by their issuer, so it missed those.
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

		// One UPDATE per page rather than per certificate.
		var values []string
		var args []any
		for _, r := range batch {
			certificate, err := mhelper.DecodeCertificate(r.base64Certificate)
			if err != nil {
				logger.Warnf("skipping certificate %s: could not decode it: %s", r.serialNumber, err)
				skipped++
				continue
			}

			issuer := chelpers.PkixNameToSubject(certificate.Issuer)
			n := len(args)
			values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d)", n+1, n+2, n+3, n+4, n+5, n+6, n+7))
			args = append(args, r.serialNumber, issuer.CommonName, issuer.Organization, issuer.OrganizationUnit, issuer.Country, issuer.State, issuer.Locality)
		}

		if len(values) > 0 {
			if _, err := tx.ExecContext(ctx, `
				UPDATE certificates AS c
				SET issuer_common_name = v.common_name, issuer_organization = v.organization,
				    issuer_organization_unit = v.organization_unit, issuer_country = v.country,
				    issuer_state = v.state, issuer_locality = v.locality
				FROM (VALUES `+strings.Join(values, ", ")+`) AS v(serial_number, common_name, organization, organization_unit, country, state, locality)
				WHERE c.serial_number = v.serial_number
			`, args...); err != nil {
				return fmt.Errorf("update certificate issuers: %w", err)
			}
			updated += len(values)
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
