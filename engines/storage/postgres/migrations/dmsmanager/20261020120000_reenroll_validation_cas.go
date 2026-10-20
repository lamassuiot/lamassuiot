package dmsmanager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20261020120000ReenrollValidationCAs() {
	goose.AddMigrationContext(upReenrollValidationCAs, downReenrollValidationCAs)
}

// upReenrollValidationCAs moves reenrollment_settings.additional_validation_cas into
// reenrollment_settings.est_rfc7030_settings.client_certificate_settings.validation_cas.
// The previous validation_cas value of the re-enrollment block was never used when validating
// re-enrollments (it was only a copy of the enrollment settings), so it is replaced to keep the
// effective behaviour unchanged.
func upReenrollValidationCAs(ctx context.Context, tx *sql.Tx) error {
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

		reenrollmentSettings, ok := config["reenrollment_settings"].(map[string]any)
		if !ok {
			continue
		}

		additionalCAs, exists := reenrollmentSettings["additional_validation_cas"]
		if !exists {
			continue
		}
		delete(reenrollmentSettings, "additional_validation_cas")

		if additionalCAs == nil {
			additionalCAs = []any{}
		}

		estSettings, ok := reenrollmentSettings["est_rfc7030_settings"].(map[string]any)
		if !ok {
			estSettings = map[string]any{}
			reenrollmentSettings["est_rfc7030_settings"] = estSettings
		}

		clientCertSettings, ok := estSettings["client_certificate_settings"].(map[string]any)
		if !ok {
			clientCertSettings = map[string]any{}
			estSettings["client_certificate_settings"] = clientCertSettings
		}
		clientCertSettings["validation_cas"] = additionalCAs

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

func downReenrollValidationCAs(ctx context.Context, tx *sql.Tx) error {
	return nil
}
