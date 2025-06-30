package dmsmanager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20250612100530ESTVerifyCSRSignature() {
	goose.AddMigrationContext(upDms, downDms)
}

func upDms(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is applied.
	rows, err := tx.QueryContext(ctx, "SELECT * FROM dms")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, r := range result {
		settings := r["settings"].(string)

		// Unmarshal the JSON into a map
		var config map[string]any
		if err := json.Unmarshal([]byte(settings), &config); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %v", err)
		}

		// set enrollment_settings.verify_csr_signature to false
		enrollmentSettings, ok := config["enrollment_settings"].(map[string]any)
		if ok {
			enrollmentSettings["verify_csr_signature"] = false
		} else {
			return fmt.Errorf("enrollment_settings not found")
		}

		// Marshal the map back into JSON
		newSettings, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}

		// Update the row
		_, err = tx.ExecContext(ctx, "UPDATE dms SET settings = $1 WHERE id = $2", string(newSettings), r["id"])
		if err != nil {
			return err
		}
	}

	return nil
}

func downDms(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
