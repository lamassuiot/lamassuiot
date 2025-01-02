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

var DMSDBName = "dmsmanager"

func MigrationTest_DMS_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, DMSDBName)

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

func MigrationTest_DMS_20241230124809_serverkeygen_revokereenroll(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
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

	ApplyMigration(t, logger, con, DMSDBName)

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

func TestDMSMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, DMSDBName)

	defer cleanup()

	MigrationTest_DMS_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	MigrationTest_DMS_20241230124809_serverkeygen_revokereenroll(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20241230124809_relational_dms")
	}
}
