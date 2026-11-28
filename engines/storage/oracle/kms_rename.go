package oracle

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"gorm.io/gorm"
)

var kmsKeyPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_kms_keys_pk\)`)

// renameKey updates the composite key and its references from certificates
// and CRL settings under a shared database lock: Oracle has no ON UPDATE
// CASCADE. Both FKs, lamassu_cert_key_fk and lamassu_crl_signer_key_fk, must
// be DEFERRABLE. The migration must seed the kms_rename lock row.
//
// The engine is renamed last, after both updates succeed: it cannot be rolled
// back, so any database failure (such as a taken target key) must happen
// first. A failure of the callback rolls the updates back. Only a failure to
// commit can still leave the engine renamed and the database unchanged.
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
		// Certificates and CRL settings still reference the old key until they are updated below.
		if err := tx.Exec("SET CONSTRAINTS lamassu_cert_key_fk, lamassu_crl_signer_key_fk DEFERRED").Error; err != nil {
			return err
		}
		result := tx.Exec("UPDATE kms_keys SET key_id = ?, aliases = ? WHERE key_id = ? AND engine_id = ?", newKeyID, string(encoded), oldKeyID, engineID)
		if constraintError(result.Error, "ORA-00001", kmsKeyPK) {
			return fmt.Errorf("rename key %s to %s in engine %s: %w", oldKeyID, newKeyID, engineID, gorm.ErrDuplicatedKey)
		}
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("rename key: expected one key, updated %d", result.RowsAffected)
		}
		if err := tx.Exec("UPDATE certificates SET key_id = ? WHERE key_id = ? AND engine_id = ?", newKeyID, oldKeyID, engineID).Error; err != nil {
			return err
		}
		if err := tx.Exec("UPDATE crl_settings SET signer_key_id = ? WHERE signer_key_id = ? AND signer_engine_id = ?", newKeyID, oldKeyID, engineID).Error; err != nil {
			return err
		}
		if err := renameInEngine(); err != nil {
			return err
		}
		renamed = true
		return nil
	})
	return renamed && err == nil, err
}
