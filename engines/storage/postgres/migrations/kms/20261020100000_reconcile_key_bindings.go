package kms

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	mhelper "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations/helpers"
	"github.com/pressly/goose/v3"
)

func Register20261020100000ReconcileKeyBindings() {
	goose.AddMigrationContext(upReconcileKeyBindings, downReconcileKeyBindings)
}

// keyRef is the identity of a KMS key: the same key_id can be held by several engines.
type keyRef struct {
	keyID    string
	engineID string
}

// upReconcileKeyBindings rebuilds the lamassu.io/kms/binded-resources metadata of every key from the
// certificates that use it. Earlier versions bound a certificate to its key on creation but never
// unbound it on deletion, bound some imported CAs twice, and let metadata updates edit the bindings.
// The bindings now keep a key in use from being deleted, so they must match the certificates.
//
// The CA schema lives in the same database. A certificate uses a key when it has an engine_id:
// existing CAs (deleted CAs leave their certificate behind, so CA certificates only count while
// their CA exists) and certificates whose key Lamassu generated. Bindings of other resource types
// are kept as they are.
func upReconcileKeyBindings(ctx context.Context, tx *sql.Tx) error {
	logger := chelpers.SetupLogger("info", "KMS", "Migrations")

	ready, err := caSchemaReady(ctx, tx)
	if err != nil {
		return err
	}
	if !ready {
		// A fresh installation: no certificate uses a key yet.
		logger.Infof("CA tables not found, no key bindings to reconcile")
		return nil
	}

	certsByKey, err := collectCertificateBindings(ctx, tx)
	if err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, `SELECT key_id, engine_id, COALESCE(metadata::text, '{}') FROM kms_keys`)
	if err != nil {
		return err
	}
	type kmsKeyRow struct {
		ref      keyRef
		metadata string
	}
	var keys []kmsKeyRow
	for rows.Next() {
		var row kmsKeyRow
		if err := rows.Scan(&row.ref.keyID, &row.ref.engineID, &row.metadata); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	updated := 0
	for _, key := range keys {
		metadata := map[string]any{}
		if err := json.Unmarshal([]byte(key.metadata), &metadata); err != nil || metadata == nil {
			logger.Warnf("skipping key %s in engine %s: unreadable metadata: %v", key.ref.keyID, key.ref.engineID, err)
			continue
		}

		current, hasBindings := metadata[models.KMSBindResourceKey]
		desired := append(otherBindings(current), certsByKey[key.ref]...)
		if !hasBindings && len(desired) == 0 {
			continue
		}
		if sameBindings(current, desired) {
			continue
		}

		metadata[models.KMSBindResourceKey] = desired
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE kms_keys SET metadata = $1::jsonb WHERE key_id = $2 AND engine_id = $3`,
			string(encoded), key.ref.keyID, key.ref.engineID); err != nil {
			return fmt.Errorf("could not update bindings of key %s in engine %s: %w", key.ref.keyID, key.ref.engineID, err)
		}
		updated++
	}

	logger.Infof("reconciled key bindings: %d of %d keys updated", updated, len(keys))
	return nil
}

func downReconcileKeyBindings(ctx context.Context, tx *sql.Tx) error {
	// The previous bindings were inconsistent and are not kept.
	return nil
}

// caSchemaReady reports whether the CA tables this migration reads exist.
func caSchemaReady(ctx context.Context, tx *sql.Tx) (bool, error) {
	var columns int
	err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'ca' AND (
			(table_name = 'certificates' AND column_name IN ('serial_number', 'certificate', 'engine_id', 'is_ca')) OR
			(table_name = 'ca_certificates' AND column_name = 'serial_number'))
	`).Scan(&columns)
	if err != nil {
		return false, err
	}
	return columns == 5, nil
}

// collectCertificateBindings returns, for each key, the bindings of the certificates that use it,
// sorted by serial number.
func collectCertificateBindings(ctx context.Context, tx *sql.Tx) (map[keyRef][]models.KMSBindResource, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT c.serial_number, c.certificate, c.engine_id
		FROM ca.certificates AS c
		WHERE c.engine_id IS NOT NULL AND c.engine_id <> ''
		  AND (c.is_ca = false OR EXISTS (SELECT 1 FROM ca.ca_certificates AS ca WHERE ca.serial_number = c.serial_number))
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certsByKey := map[keyRef][]models.KMSBindResource{}
	for rows.Next() {
		var serialNumber, certificate, engineID string
		if err := rows.Scan(&serialNumber, &certificate, &engineID); err != nil {
			return nil, err
		}

		cert, err := mhelper.DecodeCertificate(certificate)
		if err != nil {
			return nil, fmt.Errorf("could not decode certificate %s: %w", serialNumber, err)
		}
		keyID, err := kmsKeyID(cert)
		if err != nil {
			return nil, fmt.Errorf("could not compute the key ID of certificate %s: %w", serialNumber, err)
		}

		ref := keyRef{keyID: keyID, engineID: engineID}
		certsByKey[ref] = append(certsByKey[ref], models.KMSBindResource{
			ResourceType: models.KMSBindResourceTypeCertificate,
			ResourceID:   serialNumber,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for ref, bindings := range certsByKey {
		slices.SortFunc(bindings, func(a, b models.KMSBindResource) int { return strings.Compare(a.ResourceID, b.ResourceID) })
		certsByKey[ref] = slices.Compact(bindings)
	}
	return certsByKey, nil
}

// kmsKeyID is the ID every crypto engine gives a key: the hex SHA-256 of its DER SubjectPublicKeyInfo.
func kmsKeyID(cert *x509.Certificate) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:]), nil
}

// parseBindings reads a bindings metadata value, which earlier versions could store as an array, a
// single object, or a JSON-encoded string of either. Unreadable entries are dropped.
func parseBindings(value any) []models.KMSBindResource {
	if value == nil {
		return nil
	}
	raw, ok := value.(string)
	if !ok {
		b, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		raw = string(b)
	}

	var list []models.KMSBindResource
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		var single models.KMSBindResource
		if err := json.Unmarshal([]byte(raw), &single); err != nil {
			return nil
		}
		list = []models.KMSBindResource{single}
	}
	return slices.DeleteFunc(list, func(r models.KMSBindResource) bool { return r.ResourceType == "" || r.ResourceID == "" })
}

// otherBindings returns the bindings of resource types other than certificates, which this
// migration does not rebuild.
func otherBindings(current any) []models.KMSBindResource {
	others := []models.KMSBindResource{}
	for _, binding := range parseBindings(current) {
		if binding.ResourceType != models.KMSBindResourceTypeCertificate && !slices.Contains(others, binding) {
			others = append(others, binding)
		}
	}
	return others
}

// sameBindings reports whether the stored value is already exactly the desired list.
func sameBindings(current any, desired []models.KMSBindResource) bool {
	list, ok := current.([]any)
	if !ok || len(list) != len(desired) {
		return false
	}
	return slices.Equal(parseBindings(current), desired)
}
