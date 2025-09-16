package ca

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20250915090500UpdateSkiAki() {
	goose.AddMigrationContext(upUpdateSkiAki, downUpdateSkiAki)
}

func upUpdateSkiAki(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.

	logger := chelpers.SetupLogger("info", "CA", "Migrations")

	// 1. Get all CA certificates of type IMPORTED or EXTERNAL
	rows, err := tx.QueryContext(ctx, `
		SELECT serial_number, certificate
		FROM certificates
		WHERE is_ca = true and type IN ('IMPORTED', 'EXTERNAL')
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	// Process each CA certificate
	for _, r := range result {
		// 2. Decode PEM certificate
		cert, err := mhelper.DecodeCertificate(r["certificate"].(string))
		if err != nil {
			return err
		}

		// 3. Get SKI (or generate from public key)
		ski, err := helpers.GetSubjectKeyID(logger, cert)
		if err != nil {
			logger.Errorf("could not get Subject Key Identifier for certificate: %s: %s", r["serial_number"], err)
			continue
		}

		// 4. Get AKI (if present)
		var aki string
		akiRaw := cert.AuthorityKeyId
		if len(akiRaw) > 0 {
			aki = hex.EncodeToString(akiRaw)
		}

		// 5. Update CA certificate with SKI and AKI
		if aki != "" {
			_, err = tx.ExecContext(ctx, `
				UPDATE certificates
				SET subject_key_id = $1, authority_key_id = $2
				WHERE serial_number = $3
			`, ski, aki, r["serial_number"])
		} else {
			_, err = tx.ExecContext(ctx, `
				UPDATE certificates
				SET subject_key_id = $1
				WHERE serial_number = $2
			`, ski, r["serial_number"])
		}
		if err != nil {
			return fmt.Errorf("failed to update CA certificate %d: %w", cert.SerialNumber, err)
		}
	}

	return nil
}

func downUpdateSkiAki(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
