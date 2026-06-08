package dmsmanager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20260604110000ReenrollAuthSettings() {
	goose.AddMigrationContext(upReenrollAuthSettings, downReenrollAuthSettings)
}

func upReenrollAuthSettings(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT id, settings FROM dms")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, r := range result {
		settingsRaw, ok := r["settings"].(string)
		if !ok {
			return fmt.Errorf("invalid settings type for dms %v", r["id"])
		}

		var config map[string]any
		if err := json.Unmarshal([]byte(settingsRaw), &config); err != nil {
			return fmt.Errorf("failed to unmarshal settings for dms %v: %w", r["id"], err)
		}

		enrollmentSettings, ok := config["enrollment_settings"].(map[string]any)
		if !ok {
			continue
		}
		enrollmentESTSettings, ok := enrollmentSettings["est_rfc7030_settings"].(map[string]any)
		if !ok {
			continue
		}

		reenrollmentSettings, ok := config["reenrollment_settings"].(map[string]any)
		if !ok {
			continue
		}
		if _, exists := reenrollmentSettings["est_rfc7030_settings"]; exists {
			continue
		}

		reenrollmentSettings["est_rfc7030_settings"] = enrollmentESTSettings

		newSettings, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal settings for dms %v: %w", r["id"], err)
		}

		_, err = tx.ExecContext(ctx, "UPDATE dms SET settings = $1 WHERE id = $2", string(newSettings), r["id"])
		if err != nil {
			return err
		}
	}

	return nil
}

func downReenrollAuthSettings(ctx context.Context, tx *sql.Tx) error {
	return nil
}
