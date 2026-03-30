package migrationstest

import (
	"encoding/json"
	"os"
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

	CleanAllTables(t, logger, con)

	MigrationTest_DeviceManager_20260115161136_create_device_groups(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260115161136_create_device_groups")
	}

	CleanAllTables(t, logger, con)

	MigrationTest_DeviceManager_20260317120000_create_device_events(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260317120000_create_device_events")
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
	var identity1 string
	tx := con.Table("devices").Where("id = 'device-with-identity'").Select("identity_slot").Scan(&identity1)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	// Parse and verify JSON structure
	var identityJSON map[string]any
	err := json.Unmarshal([]byte(identity1), &identityJSON)
	assert.NoError(t, err, "Identity slot should be valid JSON")
	assert.Equal(t, "ACTIVE", identityJSON["status"])
	assert.Equal(t, float64(1), identityJSON["active_version"])

	// Verify device with empty identity_slot becomes NULL
	var identity2 *string
	tx = con.Raw("SELECT identity_slot FROM devices WHERE id = 'device-empty-identity'").Scan(&identity2)
	if tx.Error != nil {
		t.Fatalf("failed to select devices row: %v", tx.Error)
	}
	assert.Nil(t, identity2, "Empty string should become NULL")

	// Verify device with NULL identity_slot remains NULL
	var identity3 *string
	tx = con.Raw("SELECT identity_slot FROM devices WHERE id = 'device-null-identity'").Scan(&identity3)
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

func MigrationTest_DeviceManager_20260115161136_create_device_groups(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, DeviceManagerDBName)

	// Insert test root group with proper UUID
	rootID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	childID := "b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22"

	con.Exec(`INSERT INTO device_groups (id, name, description, parent_id, criteria)
		VALUES($1, 'Root Group', 'A root device group', NULL, '[{"Field":"status","FilterOperation":12,"Value":"valid"}]')`, rootID)

	// Insert test child group referencing the root
	con.Exec(`INSERT INTO device_groups (id, name, description, parent_id, criteria)
		VALUES($1, 'Child Group', 'A child device group', $2, '[{"Field":"tags","FilterOperation":7,"Value":"location:madrid"}]')`, childID, rootID)

	// Verify root group
	var rootGroup map[string]any
	tx := con.Raw("SELECT * FROM device_groups WHERE id = $1", rootID).Scan(&rootGroup)
	if tx.Error != nil {
		t.Fatalf("failed to select root group: %v", tx.Error)
	}
	assert.Equal(t, rootID, rootGroup["id"])
	assert.Equal(t, "Root Group", rootGroup["name"])
	assert.Equal(t, "A root device group", rootGroup["description"])
	assert.Nil(t, rootGroup["parent_id"], "Root group should have NULL parent_id")
	assert.NotNil(t, rootGroup["created_at"])
	assert.NotNil(t, rootGroup["updated_at"])

	// Verify criteria is JSONB
	var criteriaJSON string
	tx = con.Raw("SELECT criteria FROM device_groups WHERE id = $1", rootID).Scan(&criteriaJSON)
	if tx.Error != nil {
		t.Fatalf("failed to query criteria: %v", tx.Error)
	}
	assert.Contains(t, criteriaJSON, "status")

	// Verify child group and foreign key relationship
	var childGroup map[string]any
	tx = con.Raw("SELECT * FROM device_groups WHERE id = $1", childID).Scan(&childGroup)
	if tx.Error != nil {
		t.Fatalf("failed to select child group: %v", tx.Error)
	}
	assert.Equal(t, childID, childGroup["id"])
	assert.Equal(t, "Child Group", childGroup["name"])
	assert.Equal(t, rootID, childGroup["parent_id"])

	// Verify unique constraint on name
	duplicateID := "c2eebc99-9c0b-4ef8-bb6d-6bb9bd380a33"
	tx = con.Exec(`INSERT INTO device_groups (id, name, description, criteria)
		VALUES($1, 'Root Group', 'Duplicate name', '[]')`, duplicateID)
	assert.Error(t, tx.Error, "Should fail on duplicate name")

	// Verify CASCADE DELETE - deleting root should delete child
	tx = con.Exec("DELETE FROM device_groups WHERE id = $1", rootID)
	if tx.Error != nil {
		t.Fatalf("failed to delete root group: %v", tx.Error)
	}

	// Check that child was cascade deleted
	var count int64
	con.Model(&struct{}{}).Table("device_groups").Where("id = $1", childID).Count(&count)
	assert.Equal(t, int64(0), count, "Child group should be cascade deleted")

	// Verify indexes exist
	var indexCount int64
	con.Raw(`SELECT COUNT(*) FROM pg_indexes 
		WHERE tablename = 'device_groups' 
		AND indexname IN ('idx_device_groups_parent', 'idx_device_groups_name')`).Scan(&indexCount)
	assert.Equal(t, int64(2), indexCount, "Should have both indexes")
}

func MigrationTest_DeviceManager_20260317120000_create_device_events(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Insert test device with legacy events payload in devices.events
	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-with-events', '{}', 'ACTIVE', 'device', '#FF0000', '2026-03-17 10:00:00+00', '{}', 'test-dms', '{}', '{}',
		'{"2026-03-17T10:30:00Z":{"type":"CREATED","description":"created"},"2026-03-17T11:30:00Z":{"type":"STATUS-UPDATED","description":"status changed","source":"legacy","details":{"from":"NO_IDENTITY","to":"ACTIVE"}},"2026-03-17T12:00:00Z":{"type":"CREATED","description":"created from main format"}}');
	`)

	// Insert another device without events to validate migration robustness
	con.Exec(`INSERT INTO devices
		(id, tags, status, icon, icon_color, creation_timestamp, metadata, dms_owner, identity_slot, extra_slots, events)
		VALUES('device-without-events', '{}', 'NO_IDENTITY', 'device', '#00FF00', '2026-03-17 10:00:00+00', '{}', 'test-dms', NULL, '{}', NULL);
	`)

	// Insert real-world device data from production-like SQL dump (4 devices with ~218 events total)
	sqlData, err := os.ReadFile("testdata/devices_202603301338.sql")
	if err != nil {
		t.Fatalf("failed to read testdata/devices_202603301338.sql: %v", err)
	}
	tx := con.Exec(string(sqlData))
	if tx.Error != nil {
		t.Fatalf("failed to insert real-world device data: %v", tx.Error)
	}

	ApplyMigration(t, logger, con, DeviceManagerDBName)

	// Verify events column was removed from devices table
	var eventsColumnCount int64
	tx = con.Raw(`SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'events'`).Scan(&eventsColumnCount)
	if tx.Error != nil {
		t.Fatalf("failed to inspect devices columns: %v", tx.Error)
	}
	assert.Equal(t, int64(0), eventsColumnCount, "devices.events column should be removed")

	// Verify migrated events exist in normalized table
	var migratedEventsCount int64
	tx = con.Raw("SELECT COUNT(*) FROM device_events WHERE device_id = 'device-with-events'").Scan(&migratedEventsCount)
	if tx.Error != nil {
		t.Fatalf("failed to count device_events rows: %v", tx.Error)
	}
	assert.Equal(t, int64(3), migratedEventsCount, "expected three migrated events")

	// Verify status-updated event mapped legacy source into source column
	var source string
	tx = con.Raw(`
		SELECT source
		FROM device_events
		WHERE device_id = 'device-with-events' AND event_type = 'STATUS-UPDATED'
		LIMIT 1
	`).Scan(&source)
	if tx.Error != nil {
		t.Fatalf("failed to query migrated event data: %v", tx.Error)
	}
	assert.Equal(t, "legacy", source)

	// Verify status-updated event data payload preserved extra fields
	var fromInData string
	tx = con.Raw(`
		SELECT structured_fields->'details'->>'from'
		FROM device_events
		WHERE device_id = 'device-with-events' AND event_type = 'STATUS-UPDATED'
		LIMIT 1
	`).Scan(&fromInData)
	if tx.Error != nil {
		t.Fatalf("failed to query migrated event details payload: %v", tx.Error)
	}
	assert.Equal(t, "NO_IDENTITY", fromInData)

	// Verify main-format created event receives default source and empty structured_fields
	var createdEventSource string
	tx = con.Raw(`
		SELECT source
		FROM device_events
		WHERE device_id = 'device-with-events' AND event_type = 'CREATED' AND description = 'created from main format'
		LIMIT 1
	`).Scan(&createdEventSource)
	if tx.Error != nil {
		t.Fatalf("failed to query created event source: %v", tx.Error)
	}
	assert.Equal(t, "service/devmanager", createdEventSource)

	var createdEventPayload string
	tx = con.Raw(`
		SELECT COALESCE(structured_fields::text, '{}')
		FROM device_events
		WHERE device_id = 'device-with-events' AND event_type = 'CREATED' AND description = 'created from main format'
		LIMIT 1
	`).Scan(&createdEventPayload)
	if tx.Error != nil {
		t.Fatalf("failed to query created event structured fields: %v", tx.Error)
	}
	assert.Equal(t, "{}", createdEventPayload)

	// Verify no events migrated for device with NULL events payload
	var noEventsCount int64
	tx = con.Raw("SELECT COUNT(*) FROM device_events WHERE device_id = 'device-without-events'").Scan(&noEventsCount)
	if tx.Error != nil {
		t.Fatalf("failed to count events for device-without-events: %v", tx.Error)
	}
	assert.Equal(t, int64(0), noEventsCount)

	// ---- Real-world data assertions ----
	// Verify migrated event counts per device from production SQL dump
	expectedCounts := map[string]int64{
		"device_1": 58,
		"device_2": 82,
		"device_3": 41,
		"device_4": 37,
	}

	for deviceID, expectedCount := range expectedCounts {
		var count int64
		tx = con.Raw("SELECT COUNT(*) FROM device_events WHERE device_id = ?", deviceID).Scan(&count)
		if tx.Error != nil {
			t.Fatalf("failed to count events for %s: %v", deviceID, tx.Error)
		}
		assert.Equal(t, expectedCount, count, "Event count mismatch for %s", deviceID)
	}

	// Verify total: 218 (real-world) + 3 (simple test device) = 221
	var totalEvents int64
	tx = con.Raw("SELECT COUNT(*) FROM device_events").Scan(&totalEvents)
	if tx.Error != nil {
		t.Fatalf("failed to count total events: %v", tx.Error)
	}
	assert.Equal(t, int64(221), totalEvents, "Total events: 218 real-world + 3 test")

	// Each real-world device should have exactly 1 CREATED event
	for _, deviceID := range []string{"device_1", "device_2", "device_3", "device_4"} {
		var createdCount int64
		tx = con.Raw("SELECT COUNT(*) FROM device_events WHERE device_id = ? AND event_type = 'CREATED'", deviceID).Scan(&createdCount)
		if tx.Error != nil {
			t.Fatalf("failed to count CREATED events for %s: %v", deviceID, tx.Error)
		}
		assert.Equal(t, int64(1), createdCount, "Device %s should have exactly 1 CREATED event", deviceID)
	}

	// All real-world events should have source defaulted to 'service/devmanager' (no source in original data)
	var nonDefaultSourceCount int64
	tx = con.Raw(`SELECT COUNT(*) FROM device_events 
		WHERE device_id IN ('device_1','device_2','device_3','device_4') 
		AND source != 'service/devmanager'`).Scan(&nonDefaultSourceCount)
	if tx.Error != nil {
		t.Fatalf("failed to check sources: %v", tx.Error)
	}
	assert.Equal(t, int64(0), nonDefaultSourceCount, "All real-world events should use default source")

	// Verify all timestamps from real-world data fall within March 2026
	var invalidTsCount int64
	tx = con.Raw(`SELECT COUNT(*) FROM device_events 
		WHERE device_id IN ('device_1','device_2','device_3','device_4') 
		AND (event_ts < '2026-03-01' OR event_ts > '2026-04-01')`).Scan(&invalidTsCount)
	if tx.Error != nil {
		t.Fatalf("failed to check timestamps: %v", tx.Error)
	}
	assert.Equal(t, int64(0), invalidTsCount, "All real-world timestamps should be in March 2026")

	// Verify all 4 real-world devices still exist in the devices table
	var realDeviceCount int64
	tx = con.Raw("SELECT COUNT(*) FROM devices WHERE id IN ('device_1','device_2','device_3','device_4')").Scan(&realDeviceCount)
	if tx.Error != nil {
		t.Fatalf("failed to count real-world devices: %v", tx.Error)
	}
	assert.Equal(t, int64(4), realDeviceCount, "All 4 real-world devices should still exist")

	// Verify wfx events have non-empty description (the nested JSON job data)
	var emptyDescWfxCount int64
	tx = con.Raw(`SELECT COUNT(*) FROM device_events 
		WHERE device_id IN ('device_1','device_2','device_3','device_4') 
		AND event_type = 'lamaassu.io/device-event/wfx/update/job' 
		AND (description IS NULL OR description = '')`).Scan(&emptyDescWfxCount)
	if tx.Error != nil {
		t.Fatalf("failed to check wfx event descriptions: %v", tx.Error)
	}
	assert.Equal(t, int64(0), emptyDescWfxCount, "All wfx events should have non-empty descriptions")
}
