package ca

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20250123125500CaAwsMetadata() {
	goose.AddMigrationContext(upCaAwsMetadata, downCaAwsMetadata)
}

func upCaAwsMetadata(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT * FROM ca_certificates")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, r := range result {
		metadataStr := r["metadata"].(string)

		// Unmarshal the JSON into a map
		var metadata map[string]interface{}
		if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %v", err)
		}

		shouldUpdate := false

		// Check if the there is any metadata for aws starting with "lamassu.io/iot/aws."
		for key, value := range metadata {
			if strings.HasPrefix(key, "lamassu.io/iot/aws.") {
				awsMeta := value.(map[string]interface{})

				// Now, if there is a key named "register", it means the metadata is in the old format. New format contains "registration" key instead.
				if registered, ok := awsMeta["register"]; ok {
					fmt.Println("Updating metadata for CA certificate with ID:", r["id"])
					shouldUpdate = true

					if registered.(bool) {
						awsMeta["registration"] = map[string]interface{}{
							"status":                    "SUCCEEDED",
							"registration_request_time": time.Unix(0, 0).In(time.UTC),
							"registration_time":         time.Unix(0, 0).In(time.UTC),
							"primary_account":           true,
							"error":                     "",
						}
					} else {
						awsMeta["registration"] = map[string]interface{}{
							"status": "FAILED",
						}
					}

					delete(awsMeta, "register")
					metadata[key] = awsMeta
				}
			}
		}

		if shouldUpdate {
			// Marshal the map back into JSON
			metadataStr, err := json.Marshal(metadata)
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %v", err)
			}

			// Update the row
			_, err = tx.ExecContext(ctx, "UPDATE ca_certificates SET metadata = $1 WHERE id = $2", string(metadataStr), r["id"])
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func downCaAwsMetadata(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
