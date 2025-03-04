package dmsmanager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20241230124809ServerkeygenRevokereenroll() {
	goose.AddMigrationContext(upRelationalDms, downRelationalDms)
}

func upRelationalDms(ctx context.Context, tx *sql.Tx) error {
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
		var config map[string]interface{}
		if err := json.Unmarshal([]byte(settings), &config); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %v", err)
		}

		// Check if the server_keygen_settings field exists. If not, create it and set 'enabled' to false
		if _, ok := config["server_keygen_settings"].(map[string]interface{}); !ok {
			config["server_keygen_settings"] = map[string]interface{}{
				"enabled": false,
			}
		}

		// set reenrollment_settings.revoke_on_reenrollment to false
		if _, ok := config["reenrollment_settings"].(map[string]interface{}); ok {
			config["reenrollment_settings"].(map[string]interface{})["revoke_on_reenrollment"] = false
		} else {
			return fmt.Errorf("reenrollment_settings not found")
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

func downRelationalDms(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
