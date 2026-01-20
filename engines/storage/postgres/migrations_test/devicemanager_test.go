package migrationstest

import (
	"encoding/json"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

var DeviceManagerDBName = "devicemanager"

func MigrationTest_DeviceManager_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, DeviceManagerDBName)

	// Insert test device data
	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('test-device-1', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '{}', 'test-dms', '{}', '{}', '{}');
	`)

	var result map[string]any
	tx := con.Raw("SELECT * FROM devices WHERE id = 'test-device-1'").Scan(&result)
	if tx.RowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", tx.RowsAffected)
	}

	assert.Equal(t, "test-device-1", result["id"])
	assert.Equal(t, "ACTIVE", result["status"])
	assert.Equal(t, "test-dms", result["dms_owner"])
}

func MigrationTest_DeviceManager_20250925120000_remove_serial_hyphens(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Clean the table first to avoid counting the test device from the previous test
	CleanAllTables(t, logger, con)

	// Test data with various scenarios
	testCases := []struct {
		name                 string
		deviceID             string
		inputIdentitySlot    string
		expectedIdentitySlot string
		shouldUpdate         bool
	}{
		{
			name:     "Device with hyphenated serial numbers",
			deviceID: "device-with-hyphens",
			inputIdentitySlot: `{
				"status": "EXPIRED",
				"active_version": 2,
				"type": "x509",
				"versions": {
					"0": "02-F4-D5-4B-50-BF-26-BA-75-27-68-20-55-51-A9-25",
					"1": "42-BD-E9-FC-7A-CC-25-20-EB-91-3E-DE-21-50-F4-1D",
					"2": "77-70-B4-07-8C-A0-4C-52-EE-0B-37-DE-98-22-95-7B"
				},
				"events": {}
			}`,
			expectedIdentitySlot: `{
				"status": "EXPIRED",
				"active_version": 2,
				"type": "x509",
				"versions": {
					"0": "02f4d54b50bf26ba752768205551a925",
					"1": "42bde9fc7acc2520eb913ede2150f41d",
					"2": "7770b4078ca04c52ee0b37de9822957b"
				},
				"events": {}
			}`,
			shouldUpdate: true,
		},
		{
			name:     "Device with already clean serial numbers",
			deviceID: "device-clean-serials",
			inputIdentitySlot: `{
				"status": "ACTIVE",
				"active_version": 1,
				"type": "x509",
				"versions": {
					"0": "02f4d54b50bf26ba75276820555a925",
					"1": "42bde9fc7acc2520eb913ede2150f41d"
				},
				"events": {}
			}`,
			expectedIdentitySlot: `{
				"status": "ACTIVE",
				"active_version": 1,
				"type": "x509",
				"versions": {
					"0": "02f4d54b50bf26ba75276820555a925",
					"1": "42bde9fc7acc2520eb913ede2150f41d"
				},
				"events": {}
			}`,
			shouldUpdate: false,
		},
		{
			name:     "Device with mixed case and hyphens",
			deviceID: "device-mixed-case",
			inputIdentitySlot: `{
				"status": "ACTIVE",
				"active_version": 0,
				"type": "x509",
				"versions": {
					"0": "aa-BB-CC-DD-EE-ff-11-22-33-44-55-66-77-88-99-00"
				},
				"events": {}
			}`,
			expectedIdentitySlot: `{
				"status": "ACTIVE",
				"active_version": 0,
				"type": "x509",
				"versions": {
					"0": "aabbccddeeff11223344556677889900"
				},
				"events": {}
			}`,
			shouldUpdate: true,
		},
		{
			name:     "Device with empty versions",
			deviceID: "device-empty-versions",
			inputIdentitySlot: `{
				"status": "INACTIVE",
				"active_version": null,
				"type": "x509",
				"versions": {},
				"events": {}
			}`,
			expectedIdentitySlot: `{
				"status": "INACTIVE",
				"active_version": null,
				"type": "x509",
				"versions": {},
				"events": {}
			}`,
			shouldUpdate: false,
		},
		{
			name:                 "Device with null identity_slot",
			deviceID:             "device-null-identity",
			inputIdentitySlot:    "",
			expectedIdentitySlot: "",
			shouldUpdate:         false,
		},
	}

	// Insert test devices before migration
	for _, tc := range testCases {
		identitySlot := tc.inputIdentitySlot
		if identitySlot == "" {
			identitySlot = "NULL"
		} else {
			identitySlot = "'" + identitySlot + "'"
		}

		query := `INSERT INTO devices
			(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
			VALUES(?, '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '{}', 'test-dms', ` + identitySlot + `, '{}', '{}');`

		con.Exec(query, tc.deviceID)
	}

	// Apply the migration
	ApplyMigration(t, logger, con, DeviceManagerDBName)

	// Verify the results
	for _, tc := range testCases {
		var actualIdentitySlot *string
		tx := con.Raw("SELECT identity_slot FROM devices WHERE id = ?", tc.deviceID).Scan(&actualIdentitySlot)
		if tx.Error != nil {
			t.Fatalf("failed to select device %s: %v", tc.deviceID, tx.Error)
		}

		if tc.expectedIdentitySlot == "" {
			// Expect NULL
			assert.Nil(t, actualIdentitySlot, "Device %s should have NULL identity_slot", tc.name)
		} else {
			// Expect JSON content - compare by unmarshaling both to avoid whitespace/ordering issues
			assert.NotNil(t, actualIdentitySlot, "Device %s should have non-NULL identity_slot", tc.name)

			var expectedJSON, actualJSON map[string]any
			err := json.Unmarshal([]byte(tc.expectedIdentitySlot), &expectedJSON)
			assert.NoError(t, err, "Expected JSON should be valid for %s", tc.name)

			err = json.Unmarshal([]byte(*actualIdentitySlot), &actualJSON)
			assert.NoError(t, err, "Actual JSON should be valid for %s", tc.name)

			assert.Equal(t, expectedJSON, actualJSON, "Identity slot JSON should match for %s", tc.name)
		}
	}

	// Verify total number of devices
	var count int64
	con.Model(&struct{}{}).Table("devices").Count(&count)
	assert.Equal(t, int64(len(testCases)), count, "Should have the expected number of devices")
}

func TestDeviceManagerMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Trace, "test", "test")
	cleanup, con := RunDB(t, logger, DeviceManagerDBName)
	defer cleanup()

	MigrationTest_DeviceManager_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	MigrationTest_DeviceManager_20250925120000_remove_serial_hyphens(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20250925120000_remove_serial_hyphens")
	}

	CleanAllTables(t, logger, con)

	MigrationTest_DeviceManager_20251217120000_metadata_text_to_jsonb(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20251217120000_metadata_text_to_jsonb")
	}

	CleanAllTables(t, logger, con)

	MigrationTest_DeviceManager_20260120114735_idslot_text_to_jsonb(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260120114735_idslot_text_to_jsonb")
	}
}

func MigrationTest_DeviceManager_20251217120000_metadata_text_to_jsonb(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Insert test devices with text metadata before migration
	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-with-metadata', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '{"device_key":"device_value","count":42}', 'test-dms', '{}', '{}', '{}');
	`)

	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-empty-metadata', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '', 'test-dms', '{}', '{}', '{}');
	`)

	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-null-metadata', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', NULL, 'test-dms', '{}', '{}', '{}');
	`)

	// Apply migration
	ApplyMigration(t, logger, con, DeviceManagerDBName)

	// Verify device with metadata
	var metadata1 string
	tx := con.Table("devices").Where("id = 'device-with-metadata'").Select("metadata").Find(&metadata1)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.Equal(t, `{"count": 42, "device_key": "device_value"}`, metadata1)

	// Verify device with empty metadata becomes empty object
	var metadata2 string
	tx = con.Table("devices").Where("id = 'device-empty-metadata'").Select("metadata").Find(&metadata2)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.Equal(t, `{}`, metadata2)

	// Verify device with NULL metadata becomes empty object
	var metadata3 string
	tx = con.Table("devices").Where("id = 'device-null-metadata'").Select("metadata").Find(&metadata3)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.Equal(t, `{}`, metadata3)

	// Verify that the column type is jsonb by trying to use jsonb operators
	var keyValue string
	tx = con.Raw("SELECT metadata->>'device_key' FROM devices WHERE id = 'device-with-metadata'").Scan(&keyValue)
	if tx.Error != nil {
		t.Fatalf("failed to query jsonb column: %v", tx.Error)
	}
	assert.Equal(t, "device_value", keyValue)
}

func MigrationTest_DeviceManager_20260120114735_idslot_text_to_jsonb(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Insert test devices with text identity_slot before migration
	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-with-identity', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '{}', 'test-dms', '{"status":"ACTIVE","active_version":1,"type":"x509","versions":{"0":"cert-serial-1","1":"cert-serial-2"},"events":{}}', '{}', '{}');
	`)

	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-empty-identity', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '{}', 'test-dms', '', '{}', '{}');
	`)

	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-null-identity', '{}', 'ACTIVE', 'device', '#FF0000', '2024-11-25 11:45:48.620', '{}', 'test-dms', NULL, '{}', '{}');
	`)

	// Apply migration
	ApplyMigration(t, logger, con, DeviceManagerDBName)

	// Verify device with identity_slot
	var identity1 *string
	tx := con.Table("devices").Where("id = 'device-with-identity'").Select("identity_slot").Find(&identity1)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.NotNil(t, identity1)
	// Parse and verify JSON structure
	var identityJSON map[string]any
	err := json.Unmarshal([]byte(*identity1), &identityJSON)
	assert.NoError(t, err, "Identity slot should be valid JSON")
	assert.Equal(t, "ACTIVE", identityJSON["status"])
	assert.Equal(t, float64(1), identityJSON["active_version"])

	// Verify device with empty identity_slot becomes NULL
	var identity2 *string
	tx = con.Table("devices").Where("id = 'device-empty-identity'").Select("identity_slot").Find(&identity2)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.Nil(t, identity2, "Empty string should become NULL")

	// Verify device with NULL identity_slot remains NULL
	var identity3 *string
	tx = con.Table("devices").Where("id = 'device-null-identity'").Select("identity_slot").Find(&identity3)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.Nil(t, identity3, "NULL should remain NULL")

	// Verify that the column type is jsonb by trying to use jsonb operators
	var status string
	tx = con.Raw("SELECT identity_slot->>'status' FROM devices WHERE id = 'device-with-identity'").Scan(&status)
	if tx.Error != nil {
		t.Fatalf("failed to query jsonb column: %v", tx.Error)
	}
	assert.Equal(t, "ACTIVE", status)

	// Test JSONPath query (RFC requirement)
	var count int64
	tx = con.Raw("SELECT COUNT(*) FROM devices WHERE identity_slot @@ '$.status == \"ACTIVE\"'::jsonpath").Scan(&count)
	if tx.Error != nil {
		t.Fatalf("failed to query with jsonpath: %v", tx.Error)
	}
	assert.Equal(t, int64(1), count, "Should find one device with ACTIVE status")
}
