package dmsmanager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	mhelper "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20260801120000ProtocolScopedSettings() {
	goose.AddMigrationContext(upProtocolScopedSettings, downProtocolScopedSettings)
}

// upProtocolScopedSettings reshapes dms.settings from the flat layout
//
//	{server_keygen_settings, enrollment_settings{protocol, est_rfc7030_settings, ...},
//	 reenrollment_settings{est_rfc7030_settings, ...}, ca_distribution_settings,
//	 issuance_profile_id, issuance_profile}
//
// into the protocol-scoped one
//
//	{protocol, est_settings{server_keygen_settings, enrollment_settings,
//	 reenrollment_settings, ca_distribution_settings, issuance_profile_id,
//	 issuance_profile}}
//
// hoisting the protocol discriminator to the top and folding every other block
// into the container for the protocol the DMS actually speaks. The nested
// est_rfc7030_settings wrappers are spliced up one level: the enclosing
// est_settings already identifies the protocol.
//
// Every stored DMS is necessarily EST — CMP support was added after this
// layout and never shipped under it — so there is no cmp_settings branch here.
// A row whose protocol says otherwise is left untouched rather than guessed at.
func upProtocolScopedSettings(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT id, settings FROM dms")
	if err != nil {
		return err
	}

	result, err := mhelper.RowsToMap(rows)
	if err != nil {
		return err
	}

	for _, r := range result {
		settingsRaw, err := settingsBytes(r["settings"])
		if err != nil {
			return fmt.Errorf("invalid settings for dms %v: %w", r["id"], err)
		}

		var config map[string]any
		if err := json.Unmarshal(settingsRaw, &config); err != nil {
			return fmt.Errorf("failed to unmarshal settings for dms %v: %w", r["id"], err)
		}

		// Idempotency: a row already carrying a top-level protocol has been
		// reshaped (by this migration, or written by a post-refactor server).
		if _, done := config["protocol"]; done {
			continue
		}

		enrollment, ok := config["enrollment_settings"].(map[string]any)
		if !ok {
			continue
		}

		protocol, _ := enrollment["protocol"].(string)
		if protocol != "EST_RFC7030" {
			continue
		}
		delete(enrollment, "protocol")
		spliceUp(enrollment, "est_rfc7030_settings")

		reenrollment, ok := config["reenrollment_settings"].(map[string]any)
		if !ok {
			reenrollment = map[string]any{}
		}
		spliceUp(reenrollment, "est_rfc7030_settings")

		est := map[string]any{
			"enrollment_settings":   enrollment,
			"reenrollment_settings": reenrollment,
		}
		// Carry the remaining blocks across only when present, so a DMS that
		// never had one does not gain an explicit null.
		for _, key := range []string{
			"server_keygen_settings",
			"ca_distribution_settings",
			"issuance_profile_id",
			"issuance_profile",
		} {
			if v, exists := config[key]; exists {
				est[key] = v
			}
		}

		newSettings, err := json.Marshal(map[string]any{
			"protocol":     protocol,
			"est_settings": est,
		})
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

// spliceUp moves every key of the nested object at wrapper into parent and
// removes the wrapper, leaving parent's own keys untouched on collision.
func spliceUp(parent map[string]any, wrapper string) {
	nested, ok := parent[wrapper].(map[string]any)
	if !ok {
		delete(parent, wrapper)
		return
	}
	for k, v := range nested {
		if _, clash := parent[k]; !clash {
			parent[k] = v
		}
	}
	delete(parent, wrapper)
}

// settingsBytes normalizes the driver's scan of the settings column. It was
// migrated from text to jsonb (20260113212700_settings_text_to_jsonb.sql), and
// the two scan as different Go types depending on driver version, so accept
// both rather than assert one.
func settingsBytes(v any) ([]byte, error) {
	switch s := v.(type) {
	case string:
		return []byte(s), nil
	case []byte:
		return s, nil
	default:
		return nil, fmt.Errorf("unexpected settings type %T", v)
	}
}

func downProtocolScopedSettings(ctx context.Context, tx *sql.Tx) error {
	return nil
}
