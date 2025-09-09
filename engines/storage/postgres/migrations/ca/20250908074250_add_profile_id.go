package ca

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jakehl/goid"
	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20250908074250AddProfileId() {
	goose.AddMigrationContext(upAddProfileId, downAddProfileId)
}

func upAddProfileId(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.

	_, err := tx.Exec("ALTER TABLE ca_certificates ADD COLUMN profile_id VARCHAR;")
	if err != nil {
		tx.Rollback()
		return err
	}

	rows, err := tx.QueryContext(ctx, "SELECT * FROM ca_certificates;")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, row := range result {
		fmt.Println(row)
		caID := row["id"].(string)
		validityType := row["validity_type"].(string)
		validityDurationStr := row["validity_duration"].(string)
		validityTimeStr := row["validity_time"].(time.Time)

		uuid := goid.NewV4UUID().String()
		_, err := tx.ExecContext(ctx,
			`INSERT INTO issuance_profiles
				(id, "name", description, validity_type, validity_time, validity_duration, sign_as_ca, honor_key_usage, key_usage, honor_extended_key_usages, extended_key_usages, honor_subject, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, honor_extensions, crypto_enforcement_enabled, crypto_enforcement_allow_rsa_keys, crypto_enforcement_allowed_rsa_key_sizes, crypto_enforcement_allow_ecdsa_keys, crypto_enforcement_allowed_ecdsa_key_sizes)
				VALUES
				($1, $2, $3, $4, $5, $6, false, true, '["DigitalSignature","KeyEncipherment"]', false, '["ClientAuth","ServerAuth"]', true, '', '', '', '', '', '', true, true, true, '[2048,3072,4096]', true, '[256,384,521]');`,
			uuid,
			fmt.Sprintf("Auto Profile for CA %s", caID),
			fmt.Sprintf("Default Profile created automatically for CA %s", caID),
			validityType,
			validityTimeStr,
			validityDurationStr,
		)
		if err != nil {
			tx.Rollback()
			return err
		}

		_, err = tx.ExecContext(ctx, `
				UPDATE ca_certificates 
				SET 
					profile_id = $1
				WHERE id = $2
			`,
			uuid,
			caID,
		)
		if err != nil {
			tx.Rollback()
			return err
		}

		fmt.Printf("Created issuance profile %s for CA %s\n", uuid, caID)

	}

	queries := []string{
		"ALTER TABLE ca_certificates DROP COLUMN validity_type;",
		"ALTER TABLE ca_certificates DROP COLUMN validity_duration;",
		"ALTER TABLE ca_certificates DROP COLUMN validity_time;",
	}

	// Execute each query in the transaction
	for _, query := range queries {
		_, err := tx.Exec(query)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return nil
}

func downAddProfileId(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.

	// First, restore the original columns that were dropped in the up migration
	queries := []string{
		"ALTER TABLE ca_certificates ADD COLUMN validity_type VARCHAR;",
		"ALTER TABLE ca_certificates ADD COLUMN validity_duration VARCHAR;",
		"ALTER TABLE ca_certificates ADD COLUMN validity_time TIMESTAMP;",
	}

	// Execute each query to restore the columns
	for _, query := range queries {
		_, err := tx.Exec(query)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Get all CA certificates with their profile information to restore the original data
	rows, err := tx.QueryContext(ctx, `
		SELECT 
			ca.id,
			ip.validity_type,
			ip.validity_duration,
			ip.validity_time
		FROM ca_certificates ca
		LEFT JOIN issuance_profiles ip ON ca.profile_id = ip.id
		WHERE ca.profile_id IS NOT NULL;
	`)
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	// Restore the original validity data for each CA certificate
	for _, row := range result {
		caID := row["id"].(string)
		validityType := row["validity_type"]
		validityDuration := row["validity_duration"]
		validityTime := row["validity_time"]

		_, err = tx.ExecContext(ctx, `
			UPDATE ca_certificates 
			SET 
				validity_type = $1,
				validity_duration = $2,
				validity_time = $3
			WHERE id = $4
		`,
			validityType,
			validityDuration,
			validityTime,
			caID,
		)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Delete the auto-created issuance profiles
	_, err = tx.ExecContext(ctx, `
		DELETE FROM issuance_profiles 
		WHERE name LIKE 'Auto Profile for CA %';
	`)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Finally, drop the profile_id column
	_, err = tx.Exec("ALTER TABLE ca_certificates DROP COLUMN profile_id;")
	if err != nil {
		tx.Rollback()
		return err
	}

	return nil
}
