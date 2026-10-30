package kms

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/pressly/goose/v3"
)

func Register20261027110000KeyBindings() {
	goose.AddMigrationContext(upKeyBindings, downKeyBindings)
}

// upKeyBindings makes the KMS the record of which resources use each key: it creates the key_bindings
// table, whose foreign key keeps a bound key from being deleted, and moves there the bindings earlier
// versions kept in the key metadata.
func upKeyBindings(ctx context.Context, tx *sql.Tx) error {
	for _, query := range []string{
		// The resources that use each engine's copy of a key. A key with bindings cannot be deleted:
		// the foreign key enforces it for every path, not only for the CA service. Renaming a key
		// carries its bindings along.
		`CREATE TABLE key_bindings (
			key_id        text        NOT NULL,
			engine_id     text        NOT NULL,
			resource_type text        NOT NULL,
			resource_id   text        NOT NULL,
			created_at    timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT key_bindings_pkey PRIMARY KEY (key_id, engine_id, resource_type, resource_id),
			CONSTRAINT key_bindings_key_fk FOREIGN KEY (key_id, engine_id)
				REFERENCES kms_keys (key_id, engine_id) ON DELETE RESTRICT ON UPDATE CASCADE
		)`,
		`CREATE INDEX key_bindings_resource_idx ON key_bindings (resource_type, resource_id)`,
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	return moveLegacyKeyBindings(ctx, tx)
}

// downKeyBindings puts the bindings back in the key metadata, where earlier versions read them, and
// drops the table.
func downKeyBindings(ctx context.Context, tx *sql.Tx) error {
	if err := restoreLegacyKeyBindings(ctx, tx); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DROP TABLE key_bindings`)
	return err
}

// moveLegacyKeyBindings moves the bindings that earlier versions kept in each key's metadata into
// the key_bindings table, and removes them from the metadata. Unreadable entries are left as they
// are; the certificate bindings backfill that follows rebuilds the bindings from the certificates.
func moveLegacyKeyBindings(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "KMS", "Migrations")

	rows, err := tx.QueryContext(ctx, `SELECT key_id, engine_id, metadata -> $1 FROM kms_keys WHERE metadata ? $1`, models.KMSBindResourceKey)
	if err != nil {
		return err
	}
	type legacyKey struct {
		keyID, engineID string
		bindings        []byte
	}
	var keys []legacyKey
	for rows.Next() {
		var k legacyKey
		if err := rows.Scan(&k.keyID, &k.engineID, &k.bindings); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	moved := 0
	for _, k := range keys {
		resources, ok := parseLegacyBindings(k.bindings)
		if !ok {
			logger.Warnf("leaving the unreadable bindings of key %s in engine %s in its metadata", k.keyID, k.engineID)
			continue
		}

		for _, r := range resources {
			if r.ResourceType == "" || r.ResourceID == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO key_bindings (key_id, engine_id, resource_type, resource_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
				k.keyID, k.engineID, r.ResourceType, r.ResourceID); err != nil {
				return fmt.Errorf("could not move bindings of key %s in engine %s: %w", k.keyID, k.engineID, err)
			}
		}

		if _, err := tx.ExecContext(ctx, `UPDATE kms_keys SET metadata = metadata - $1 WHERE key_id = $2 AND engine_id = $3`,
			models.KMSBindResourceKey, k.keyID, k.engineID); err != nil {
			return err
		}
		moved++
	}

	logger.Infof("moved the bindings of %d of %d keys from their metadata", moved, len(keys))
	return nil
}

// parseLegacyBindings reads a bindings metadata value, which earlier versions stored as a list, a
// single object, or a JSON string holding either.
func parseLegacyBindings(raw []byte) ([]models.KMSBindResource, bool) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		raw = []byte(encoded)
	}

	var list []models.KMSBindResource
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, true
	}

	var single models.KMSBindResource
	if err := json.Unmarshal(raw, &single); err == nil {
		return []models.KMSBindResource{single}, true
	}

	return nil, false
}

// restoreLegacyKeyBindings puts the bindings back in each key's metadata.
func restoreLegacyKeyBindings(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE kms_keys AS k
		SET metadata = COALESCE(k.metadata, '{}'::jsonb) || jsonb_build_object($1::text, b.bindings)
		FROM (
			SELECT key_id, engine_id,
				jsonb_agg(jsonb_build_object('resource_type', resource_type, 'resource_id', resource_id) ORDER BY resource_type, resource_id) AS bindings
			FROM key_bindings
			GROUP BY key_id, engine_id
		) AS b
		WHERE k.key_id = b.key_id AND k.engine_id = b.engine_id
	`, models.KMSBindResourceKey)
	return err
}
