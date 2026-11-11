package oracle

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// renameKey updates the composite key and its certificate references under a
// shared database lock. The certificate FK must be DEFERRABLE and named
// lamassu_cert_key_fk. The migration must seed the kms_rename lock row.
// As with PostgreSQL, the external callback cannot be rolled back if the SQL
// transaction subsequently fails to commit.
func renameKey(ctx context.Context, db *gorm.DB, engineID, oldKeyID, newKeyID string, renameInEngine func() error) (bool, error) {
	renamed := false
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lockID string
		if err := tx.Raw("SELECT lock_id FROM lamassu_locks WHERE lock_id = ? FOR UPDATE", "kms_rename").Row().Scan(&lockID); err != nil {
			return fmt.Errorf("lock KMS rename: %w", err)
		}
		var aliasesJSON sql.NullString
		err := tx.Raw(`SELECT JSON_SERIALIZE(aliases RETURNING CLOB) FROM kms_keys WHERE key_id = ? AND engine_id = ? FOR UPDATE`, oldKeyID, engineID).Row().Scan(&aliasesJSON)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		aliases := []string{}
		if aliasesJSON.Valid {
			if err := json.Unmarshal([]byte(aliasesJSON.String), &aliases); err != nil {
				return fmt.Errorf("decode key aliases: %w", err)
			}
		}
		aliases = append(aliases, oldKeyID)
		encoded, err := json.Marshal(aliases)
		if err != nil {
			return err
		}
		if err := tx.Exec("SET CONSTRAINTS lamassu_cert_key_fk DEFERRED").Error; err != nil {
			return err
		}
		if err := renameInEngine(); err != nil {
			return err
		}
		result := tx.Exec("UPDATE kms_keys SET key_id = ?, aliases = ? WHERE key_id = ? AND engine_id = ?", newKeyID, string(encoded), oldKeyID, engineID)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("rename key: expected one key, updated %d", result.RowsAffected)
		}
		if err := tx.Exec("UPDATE certificates SET key_id = ? WHERE key_id = ? AND engine_id = ?", newKeyID, oldKeyID, engineID).Error; err != nil {
			return err
		}
		renamed = true
		return nil
	})
	return renamed && err == nil, err
}
