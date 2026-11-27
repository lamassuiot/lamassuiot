package migrations38to40

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

// kmsRow is a kms_keys row of the v4 schema.
type kmsRow struct {
	ID, KeyID, EngineID, Digest string
	Aliases                     []string
	HasPrivateKey               bool
}

// kmsRows reads every kms_keys row, keyed by digest. A digest held twice in the engine would be lost here, which the
// unique (digest, engine_id) constraint already forbids; the row count asserted beside it would show it anyway.
func (e *env) kmsRows() map[string]kmsRow {
	e.t.Helper()
	var raw []struct {
		ID, KeyID, EngineID, Digest, Aliases string
		HasPrivateKey                        bool
	}
	require.NoError(e.t, e.db[postgres.KMS_SCHEMA].Raw(`SELECT id, key_id, engine_id, digest, COALESCE(aliases, '[]'::jsonb)::text AS aliases,
		has_private_key FROM kms_keys`).Scan(&raw).Error)
	rows := map[string]kmsRow{}
	for _, r := range raw {
		require.NotEmpty(e.t, r.Digest, "key %s has no digest", r.KeyID)
		row := kmsRow{ID: r.ID, KeyID: r.KeyID, EngineID: r.EngineID, Digest: r.Digest, HasPrivateKey: r.HasPrivateKey}
		require.NoError(e.t, json.Unmarshal([]byte(r.Aliases), &row.Aliases))
		rows[r.Digest] = row
	}
	require.Len(e.t, rows, len(raw), "two rows share a digest")
	return rows
}

// requireKey checks the row of a fixture's key: its name in the engine, its engine, its private key and its aliases.
func (e *env) requireKey(rows map[string]kmsRow, fx fixtureCA, keyID string, aliases []string) {
	e.t.Helper()
	row, ok := rows[fx.Digest]
	require.True(e.t, ok, "no kms_keys row for the key of %s (%s)", fx.Name, fx.Digest)
	require.Equal(e.t, keyID, row.KeyID, "key_id of %s", fx.Name)
	require.Equal(e.t, engineID, row.EngineID, "engine of %s", fx.Name)
	require.True(e.t, row.HasPrivateKey, "has_private_key of %s", fx.Name)
	require.ElementsMatch(e.t, aliases, row.Aliases, "aliases of %s", fx.Name)
}

var uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func requireDistinctUUIDs(t *testing.T, rows map[string]kmsRow) {
	t.Helper()
	seen := map[string]bool{}
	for _, row := range rows {
		require.Regexp(t, uuidShape, row.ID, "id of key %s", row.KeyID)
		require.False(t, seen[row.ID], "id %s used twice", row.ID)
		seen[row.ID] = true
	}
}

// keyIDs is the sorted list of the engine names of the rows.
func keyIDs(rows map[string]kmsRow) []string {
	ids := []string{}
	for _, row := range rows {
		ids = append(ids, row.KeyID)
	}
	return sortedStrings(ids...)
}

// certKeyID is the key ca.certificates records for the certificate of a fixture's CA.
func (e *env) certKeyID(name string) string {
	e.t.Helper()
	var keyID sql.NullString
	require.NoError(e.t, e.db[postgres.CA_SCHEMA].Raw(`SELECT c.key_id FROM certificates c
		JOIN ca_certificates a ON a.serial_number = c.serial_number WHERE a.id = ?`, e.caID[name]).Row().Scan(&keyID))
	return keyID.String
}

// requireCRLSigner checks the CRL settings the va migration made for a fixture's CA.
func (e *env) requireCRLSigner(name, signerKeyID, legacySKI string) {
	e.t.Helper()
	var s struct {
		SignerEngineID, SignerKeyID, LegacySKI, Status sql.NullString
	}
	require.NoError(e.t, e.db[postgres.VA_SCHEMA].Raw(`SELECT signer_engine_id, signer_key_id, legacy_ski, status FROM crl_settings
		WHERE ca_id = ?`, e.caID[name]).Row().Scan(&s.SignerEngineID, &s.SignerKeyID, &s.LegacySKI, &s.Status))
	require.Equal(e.t, "ACTIVE", s.Status.String, "CRL settings status of %s", name)
	require.Equal(e.t, engineID, s.SignerEngineID.String, "CRL signer engine of %s", name)
	require.Equal(e.t, signerKeyID, s.SignerKeyID.String, "CRL signer key of %s", name)
	require.Equal(e.t, legacySKI, s.LegacySKI.String, "legacy SKI of %s", name)
}
