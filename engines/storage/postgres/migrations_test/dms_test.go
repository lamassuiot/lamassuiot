package migrationstest

import (
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/stretchr/testify/assert"

	_ "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/dmsmanager"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var dmsDBName = "dmsmanager"

func migrationTest_DMS_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, dmsDBName)

	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('iot1', 'IoTThings', '{}', '2024-11-25 10:46:28.914', '{"server_keygen_settings":{"enabled":true,"key":{"type":"RSA","bits":4096}},"enrollment_settings":{"protocol":"EST_RFC7030","est_rfc7030_settings":{"auth_mode":"CLIENT_CERTIFICATE","client_certificate_settings":{"validation_cas":["9beebc5b-ba8d-4fc0-9e97-58299d30ae9f"],"chain_level_validation":-1,"allow_expired":false}},"device_provisioning_profile":{"icon":"CgBatteryFull","icon_color":"#37d67a-#333333","metadata":{},"tags":["iot"]},"enrollment_ca":"fd10a299-7cc0-47de-9f48-cdc9d79a711c","enable_replaceable_enrollment":false,"registration_mode":"JITP"},"reenrollment_settings":{"additional_validation_cas":[],"reenrollment_delta":"14w2d","enable_expired_renewal":false,"preventive_delta":"4w3d","critical_delta":"1w"},"ca_distribution_settings":{"include_system_ca":true,"include_enrollment_ca":false,"managed_cas":[]}}');
	`)

	var result map[string]interface{}
	tx := con.Raw("SELECT * FROM dms").Scan(&result)
	if tx.RowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", tx.RowsAffected)
	}

	assert.Equal(t, "iot1", result["id"])
	assert.Equal(t, "IoTThings", result["name"])
	assert.Equal(t, "{}", result["metadata"])
	assertEqualD(t, time.Date(2024, time.November, 25, 10, 46, 28, 914000000, time.UTC), result["creation_date"].(time.Time))
	assert.Equal(t, `{"server_keygen_settings":{"enabled":true,"key":{"type":"RSA","bits":4096}},"enrollment_settings":{"protocol":"EST_RFC7030","est_rfc7030_settings":{"auth_mode":"CLIENT_CERTIFICATE","client_certificate_settings":{"validation_cas":["9beebc5b-ba8d-4fc0-9e97-58299d30ae9f"],"chain_level_validation":-1,"allow_expired":false}},"device_provisioning_profile":{"icon":"CgBatteryFull","icon_color":"#37d67a-#333333","metadata":{},"tags":["iot"]},"enrollment_ca":"fd10a299-7cc0-47de-9f48-cdc9d79a711c","enable_replaceable_enrollment":false,"registration_mode":"JITP"},"reenrollment_settings":{"additional_validation_cas":[],"reenrollment_delta":"14w2d","enable_expired_renewal":false,"preventive_delta":"4w3d","critical_delta":"1w"},"ca_distribution_settings":{"include_system_ca":true,"include_enrollment_ca":false,"managed_cas":[]}}`, result["settings"])
}

func migrationTest_DMS_20241230124809_serverkeygen_revokereenroll(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	tx := con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('iot2', 'IoTThings2', '{}', '2024-11-25 10:46:28.914', '{"enrollment_settings":{"protocol":"EST_RFC7030","est_rfc7030_settings":{"auth_mode":"CLIENT_CERTIFICATE","client_certificate_settings":{"validation_cas":["9beebc5b-ba8d-4fc0-9e97-58299d30ae9f"],"chain_level_validation":-1,"allow_expired":false}},"device_provisioning_profile":{"icon":"CgBatteryFull","icon_color":"#37d67a-#333333","metadata":{},"tags":["iot"]},"enrollment_ca":"fd10a299-7cc0-47de-9f48-cdc9d79a711c","enable_replaceable_enrollment":false,"registration_mode":"JITP"},"reenrollment_settings":{"additional_validation_cas":[],"reenrollment_delta":"14w2d","enable_expired_renewal":false,"preventive_delta":"4w3d","critical_delta":"1w"},"ca_distribution_settings":{"include_system_ca":true,"include_enrollment_ca":false,"managed_cas":[]}}');
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert row: %v", tx.Error)
	}

	if tx.RowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", tx.RowsAffected)
	}

	ApplyMigration(t, logger, con, dmsDBName)

	var result string
	var config map[string]interface{}

	// Select iot1, should have the new keygen settings enabled and reenrollment_settings.revoke_on_reenrollment set to false
	tx = con.Table("dms").Where("id = 'iot1'").Select("settings").Find(&result)
	if tx.Error != nil {
		t.Fatalf("failed to select row: %v", tx.Error)
	}

	if err := json.Unmarshal([]byte(result), &config); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	assert.Equal(t, true, config["server_keygen_settings"].(map[string]interface{})["enabled"])
	assert.Equal(t, false, config["reenrollment_settings"].(map[string]interface{})["revoke_on_reenrollment"])

	// Select iot2, should have the new keygen settings set to false and reenrollment_settings.revoke_on_reenrollment set to false
	tx = con.Table("dms").Where("id = 'iot2'").Select("settings").Find(&result)
	if tx.Error != nil {
		t.Fatalf("failed to select row: %v", tx.Error)
	}

	if err := json.Unmarshal([]byte(result), &config); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	assert.Equal(t, false, config["server_keygen_settings"].(map[string]interface{})["enabled"])
	assert.Equal(t, false, config["reenrollment_settings"].(map[string]interface{})["revoke_on_reenrollment"])
}

func migrationTest_DMS_20250612100530_est_verify_csr_signature(t *testing.T, logger *logrus.Entry, con *gorm.DB) {

	// Fetch all settings before migration
	results := findAllDMSSettings(t, con)
	assert.Len(t, results, 2)

	// Assert 'verify_csr_signature' does not exist before migration
	assertVerifyCSRSignature(t, results, false, nil)

	ApplyMigration(t, logger, con, dmsDBName)

	// Fetch all settings after migration
	results = findAllDMSSettings(t, con)
	assert.Len(t, results, 2)

	// Assert 'verify_csr_signature' is set to false after migration
	assertVerifyCSRSignature(t, results, true, false)
}

func findAllDMSSettings(t *testing.T, con *gorm.DB) []string {
	var results []string
	tx := con.Table("dms").Select("settings").Find(&results)
	if tx.Error != nil {
		t.Fatalf("failed to select rows: %v", tx.Error)
	}
	return results
}

func assertVerifyCSRSignature(t *testing.T, results []string, shouldExist bool, expectedValue any) {
	for _, r := range results {
		var config map[string]any
		if err := json.Unmarshal([]byte(r), &config); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}
		enrollmentSettings, ok := config["enrollment_settings"].(map[string]any)
		assert.True(t, ok)
		val, exists := enrollmentSettings["verify_csr_signature"]
		if shouldExist {
			assert.True(t, exists)
			assert.Equal(t, expectedValue, val)
		} else {
			assert.False(t, exists)
		}
	}
}

func TestDMSMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, dmsDBName)

	defer cleanup()

	migrationTest_DMS_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	migrationTest_DMS_20241230124809_serverkeygen_revokereenroll(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20241230124809_relational_dms")
	}

	migrationTest_DMS_20250612100530_est_verify_csr_signature(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20250612100530_relational_dms")
	}

	CleanAllTables(t, logger, con)

	migrationTest_DMS_20251217120000_metadata_text_to_jsonb(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20251217120000_metadata_text_to_jsonb")
	}

	migrationTest_DMS_20260113212700_settings_text_to_jsonb(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260113212700_settings_text_to_jsonb")
	}

	migrationTest_DMS_20260604110000_reenroll_auth_settings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260604110000_reenroll_auth_settings")
	}

	CleanAllTables(t, logger, con)

	migrationTest_DMS_20260801120000_protocol_scoped_settings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260801120000_protocol_scoped_settings")
	}
}

func migrationTest_DMS_20251217120000_metadata_text_to_jsonb(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Insert test DMS entries with text metadata before migration
	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-with-metadata', 'DMS With Metadata', '{"dms_key":"dms_value","priority":1}', '2024-11-25 10:46:28.914', '{}');
	`)

	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-empty-metadata', 'DMS Empty Metadata', '', '2024-11-25 10:46:28.914', '{}');
	`)

	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-null-metadata', 'DMS Null Metadata', NULL, '2024-11-25 10:46:28.914', '{}');
	`)

	// Apply migration
	ApplyMigration(t, logger, con, dmsDBName)

	// Verify DMS with metadata
	var metadata1 string
	tx := con.Table("dms").Where("id = 'dms-with-metadata'").Select("metadata").Find(&metadata1)
	if tx.Error != nil {
		t.Fatalf("failed to select dms row: %v", tx.Error)
	}
	assert.Equal(t, `{"dms_key": "dms_value", "priority": 1}`, metadata1)

	// Verify DMS with empty metadata becomes empty object
	var metadata2 string
	tx = con.Table("dms").Where("id = 'dms-empty-metadata'").Select("metadata").Find(&metadata2)
	if tx.Error != nil {
		t.Fatalf("failed to select dms row: %v", tx.Error)
	}
	assert.Equal(t, `{}`, metadata2)

	// Verify DMS with NULL metadata becomes empty object
	var metadata3 string
	tx = con.Table("dms").Where("id = 'dms-null-metadata'").Select("metadata").Find(&metadata3)
	if tx.Error != nil {
		t.Fatalf("failed to select dms row: %v", tx.Error)
	}
	assert.Equal(t, `{}`, metadata3)

	// Verify that the column type is jsonb by trying to use jsonb operators
	var keyValue string
	tx = con.Raw("SELECT metadata->>'dms_key' FROM dms WHERE id = 'dms-with-metadata'").Scan(&keyValue)
	if tx.Error != nil {
		t.Fatalf("failed to query jsonb column: %v", tx.Error)
	}
	assert.Equal(t, "dms_value", keyValue)
}

func migrationTest_DMS_20260113212700_settings_text_to_jsonb(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-with-settings', 'DMS With Settings', '{}', '2024-11-25 10:46:28.914', '{"enrollment_settings":{"est_rfc7030_settings":{"auth_mode":"CLIENT_CERTIFICATE"}},"reenrollment_settings":{}}');
	`)

	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-empty-settings', 'DMS Empty Settings', '{}', '2024-11-25 10:46:28.914', '');
	`)

	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-null-settings', 'DMS Null Settings', '{}', '2024-11-25 10:46:28.914', NULL);
	`)

	ApplyMigration(t, logger, con, dmsDBName)

	var settings1 string
	tx := con.Table("dms").Where("id = 'dms-with-settings'").Select("settings").Find(&settings1)
	if tx.Error != nil {
		t.Fatalf("failed to select dms row: %v", tx.Error)
	}
	assert.Contains(t, settings1, `"enrollment_settings"`)

	var settings2 string
	tx = con.Table("dms").Where("id = 'dms-empty-settings'").Select("settings").Find(&settings2)
	if tx.Error != nil {
		t.Fatalf("failed to select dms row: %v", tx.Error)
	}
	assert.Equal(t, `{}`, settings2)

	var settings3 string
	tx = con.Table("dms").Where("id = 'dms-null-settings'").Select("settings").Find(&settings3)
	if tx.Error != nil {
		t.Fatalf("failed to select dms row: %v", tx.Error)
	}
	assert.Equal(t, `{}`, settings3)

	var authMode string
	tx = con.Raw("SELECT settings->'enrollment_settings'->'est_rfc7030_settings'->>'auth_mode' FROM dms WHERE id = 'dms-with-settings'").Scan(&authMode)
	if tx.Error != nil {
		t.Fatalf("failed to query jsonb settings column: %v", tx.Error)
	}
	assert.Equal(t, "CLIENT_CERTIFICATE", authMode)
}

func migrationTest_DMS_20260604110000_reenroll_auth_settings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-reenroll-backfill', 'DMS Reenroll Backfill', '{}', '2024-11-25 10:46:28.914', '{"enrollment_settings":{"est_rfc7030_settings":{"auth_mode":"EXTERNAL_WEBHOOK","external_webhook_settings":{"name":"hook","url":"https://example.com"}}},"reenrollment_settings":{"additional_validation_cas":[]}}');
	`)

	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-reenroll-existing', 'DMS Reenroll Existing', '{}', '2024-11-25 10:46:28.914', '{"enrollment_settings":{"est_rfc7030_settings":{"auth_mode":"NO_AUTH"}},"reenrollment_settings":{"est_rfc7030_settings":{"auth_mode":"CLIENT_CERTIFICATE"}}}');
	`)

	ApplyMigration(t, logger, con, dmsDBName)

	var backfilledAuth string
	tx := con.Raw("SELECT settings->'reenrollment_settings'->'est_rfc7030_settings'->>'auth_mode' FROM dms WHERE id = 'dms-reenroll-backfill'").Scan(&backfilledAuth)
	if tx.Error != nil {
		t.Fatalf("failed to query backfilled reenroll auth mode: %v", tx.Error)
	}
	assert.Equal(t, "EXTERNAL_WEBHOOK", backfilledAuth)

	var existingAuth string
	tx = con.Raw("SELECT settings->'reenrollment_settings'->'est_rfc7030_settings'->>'auth_mode' FROM dms WHERE id = 'dms-reenroll-existing'").Scan(&existingAuth)
	if tx.Error != nil {
		t.Fatalf("failed to query existing reenroll auth mode: %v", tx.Error)
	}
	assert.Equal(t, "CLIENT_CERTIFICATE", existingAuth)
}

func migrationTest_DMS_20260801120000_protocol_scoped_settings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// A fully-populated pre-refactor EST DMS.
	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-est-flat', 'DMS EST Flat', '{}', '2024-11-25 10:46:28.914', '{"server_keygen_settings":{"enabled":true,"key":{"type":"RSA","bits":4096}},"enrollment_settings":{"protocol":"EST_RFC7030","est_rfc7030_settings":{"auth_mode":"CLIENT_CERTIFICATE","client_certificate_settings":{"validation_cas":["ca-1"],"chain_level_validation":-1,"allow_expired":false}},"device_provisioning_profile":{"icon":"CgBatteryFull","icon_color":"#37d67a-#333333","metadata":{},"tags":["iot"]},"enrollment_ca":"enroll-ca","enable_replaceable_enrollment":false,"registration_mode":"JITP","verify_csr_signature":true},"reenrollment_settings":{"est_rfc7030_settings":{"auth_mode":"EXTERNAL_WEBHOOK"},"additional_validation_cas":[],"reenrollment_delta":"14w2d","enable_expired_renewal":false,"preventive_delta":"4w3d","critical_delta":"1w"},"ca_distribution_settings":{"include_system_ca":true,"include_enrollment_ca":false,"managed_cas":[]},"issuance_profile_id":"profile-1"}');
	`)

	// A row already in the new shape must be left exactly as-is (idempotency).
	con.Exec(`INSERT INTO dms
		(id, "name", metadata, creation_date, settings)
		VALUES('dms-already-scoped', 'DMS Already Scoped', '{}', '2024-11-25 10:46:28.914', '{"protocol":"CMP_RFC9483","cmp_settings":{"enrollment_settings":{"auth_mode":"NO_AUTH","enrollment_ca":"cmp-ca"}}}');
	`)

	ApplyMigration(t, logger, con, dmsDBName)

	var protocol string
	tx := con.Raw("SELECT settings->>'protocol' FROM dms WHERE id = 'dms-est-flat'").Scan(&protocol)
	if tx.Error != nil {
		t.Fatalf("failed to query hoisted protocol: %v", tx.Error)
	}
	assert.Equal(t, "EST_RFC7030", protocol, "protocol must be hoisted to the top level")

	// The old top-level blocks must be gone, folded into est_settings.
	// jsonb_exists is the function form of the `?` operator, which would
	// otherwise collide with gorm's bind placeholder.
	for _, key := range []string{"enrollment_settings", "reenrollment_settings", "ca_distribution_settings", "server_keygen_settings", "issuance_profile_id"} {
		var present bool
		tx = con.Raw("SELECT jsonb_exists(settings, ?) FROM dms WHERE id = 'dms-est-flat'", key).Scan(&present)
		if tx.Error != nil {
			t.Fatalf("failed to probe top-level key %s: %v", key, tx.Error)
		}
		assert.False(t, present, "top-level %s must move inside est_settings", key)
	}

	// est_rfc7030_settings is spliced up into enrollment_settings itself.
	var enrollAuth, reenrollAuth string
	tx = con.Raw("SELECT settings->'est_settings'->'enrollment_settings'->>'auth_mode' FROM dms WHERE id = 'dms-est-flat'").Scan(&enrollAuth)
	if tx.Error != nil {
		t.Fatalf("failed to query enrollment auth mode: %v", tx.Error)
	}
	assert.Equal(t, "CLIENT_CERTIFICATE", enrollAuth)

	tx = con.Raw("SELECT settings->'est_settings'->'reenrollment_settings'->>'auth_mode' FROM dms WHERE id = 'dms-est-flat'").Scan(&reenrollAuth)
	if tx.Error != nil {
		t.Fatalf("failed to query reenrollment auth mode: %v", tx.Error)
	}
	assert.Equal(t, "EXTERNAL_WEBHOOK", reenrollAuth)

	// The wrapper itself must be gone from both blocks.
	for _, block := range []string{"enrollment_settings", "reenrollment_settings"} {
		var present bool
		tx = con.Raw("SELECT jsonb_exists(settings->'est_settings'->?, 'est_rfc7030_settings') FROM dms WHERE id = 'dms-est-flat'", block).Scan(&present)
		if tx.Error != nil {
			t.Fatalf("failed to probe est_rfc7030_settings in %s: %v", block, tx.Error)
		}
		assert.False(t, present, "est_rfc7030_settings wrapper must be spliced away in %s", block)
	}

	// Non-auth siblings ride along into their new home.
	var enrollCA, delta, profileID string
	con.Raw("SELECT settings->'est_settings'->'enrollment_settings'->>'enrollment_ca' FROM dms WHERE id = 'dms-est-flat'").Scan(&enrollCA)
	assert.Equal(t, "enroll-ca", enrollCA)
	con.Raw("SELECT settings->'est_settings'->'reenrollment_settings'->>'reenrollment_delta' FROM dms WHERE id = 'dms-est-flat'").Scan(&delta)
	assert.Equal(t, "14w2d", delta)
	con.Raw("SELECT settings->'est_settings'->>'issuance_profile_id' FROM dms WHERE id = 'dms-est-flat'").Scan(&profileID)
	assert.Equal(t, "profile-1", profileID)

	var keygenEnabled bool
	con.Raw("SELECT (settings->'est_settings'->'server_keygen_settings'->>'enabled')::bool FROM dms WHERE id = 'dms-est-flat'").Scan(&keygenEnabled)
	assert.True(t, keygenEnabled, "server_keygen_settings must move under est_settings intact")

	// The already-scoped row is untouched: still CMP, still no est_settings.
	var scopedProtocol string
	con.Raw("SELECT settings->>'protocol' FROM dms WHERE id = 'dms-already-scoped'").Scan(&scopedProtocol)
	assert.Equal(t, "CMP_RFC9483", scopedProtocol)

	var hasEST bool
	con.Raw("SELECT jsonb_exists(settings, 'est_settings') FROM dms WHERE id = 'dms-already-scoped'").Scan(&hasEST)
	assert.False(t, hasEST, "an already-scoped row must not be reshaped again")
}
