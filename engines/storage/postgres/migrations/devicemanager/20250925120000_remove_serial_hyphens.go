package devicemanager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20250925120000RemoveSerialHyphens() {
	goose.AddMigrationContext(upRemoveSerialHyphens, downRemoveSerialHyphens)
}

func upRemoveSerialHyphens(ctx context.Context, tx *sql.Tx) error {
	// Query all devices that have identity_slot data
	rows, err := tx.QueryContext(ctx, "SELECT id, identity_slot FROM devices WHERE identity_slot IS NOT NULL AND identity_slot != ''")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, r := range result {
		deviceID := r["id"].(string)
		identitySlotStr := r["identity_slot"].(string)

		updatedIdentitySlotStr, shouldUpdate, err := processIdentitySlot(deviceID, identitySlotStr)
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
			continue
		}

		if shouldUpdate {
			_, err = tx.ExecContext(ctx, "UPDATE devices SET identity_slot = $1 WHERE id = $2", updatedIdentitySlotStr, deviceID)
			if err != nil {
				return fmt.Errorf("failed to update device %s: %v", deviceID, err)
			}
		}
	}

	return nil
}

// processIdentitySlot processes the identity_slot JSON, removes hyphens from serials, and returns the updated JSON string, a bool indicating if update is needed, and error if any.
func processIdentitySlot(deviceID, identitySlotStr string) (string, bool, error) {
	if identitySlotStr == "" {
		return "", false, nil
	}

	var identitySlot map[string]any
	if err := json.Unmarshal([]byte(identitySlotStr), &identitySlot); err != nil {
		return "", false, fmt.Errorf("failed to unmarshal identity_slot JSON for device %s: %v", deviceID, err)
	}

	shouldUpdate := false
	versions, ok := identitySlot["versions"]
	if !ok {
		return "", false, nil
	}

	versionsMap, ok := versions.(map[string]any)
	if !ok {
		return "", false, nil
	}

	for versionKey, serialNumber := range versionsMap {
		serialStr, ok := serialNumber.(string)
		if !ok {
			continue
		}
		newSerial := strings.ToLower(strings.ReplaceAll(serialStr, "-", ""))
		if newSerial != serialStr {
			versionsMap[versionKey] = newSerial
			shouldUpdate = true
			fmt.Printf("Updating serial number for device %s, version %s: %s -> %s\n",
				deviceID, versionKey, serialStr, newSerial)
		}
	}
	identitySlot["versions"] = versionsMap

	if shouldUpdate {
		updatedIdentitySlotStr, err := json.Marshal(identitySlot)
		if err != nil {
			return "", false, fmt.Errorf("failed to marshal identity_slot JSON for device %s: %v", deviceID, err)
		}
		return string(updatedIdentitySlotStr), true, nil
	}
	return "", false, nil
}

func downRemoveSerialHyphens(ctx context.Context, tx *sql.Tx) error {
	// This migration cannot be easily reversed since we don't know the original hyphen positions
	// The down migration would require storing the original format or implementing logic to guess hyphen positions
	// For now, we'll just log that this migration cannot be reversed
	fmt.Println("Warning: Cannot reverse serial number hyphen removal migration. Original hyphen positions are lost.")
	return nil
}
