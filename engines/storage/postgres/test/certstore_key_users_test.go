package postgrestest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

// The certificates that keep a KMS key in use: the current certificate of each CA, and every
// end-entity certificate whose key the KMS holds, revoked or expired ones included.
func TestCertificateStoreKeyUsers(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))
	db := suite.DB[postgres.CA_SCHEMA]
	store, err := postgres.NewCertificateRepository(logger, db)
	require.NoError(t, err)
	ctx := context.Background()

	insertCertificate := func(serial, status, keyID, engineID string, isCA bool) {
		t.Helper()
		require.NoError(t, db.Exec(`INSERT INTO certificates
			(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength, subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id, is_ca)
			VALUES(?, '{}', 'x', 'x', 0, ?, '', 'ECDSA', 256, 'HIGH', ?, '', '', '', '', '', '2026-01-01 00:00:00+00', '2027-01-01 00:00:00+00', '0001-01-01 00:00:00+00', 'Unspecified', 'MANAGED', ?, ?, ?)`,
			serial, status, serial, engineID, keyID, isCA).Error)
	}
	insertCA := func(serial string) {
		t.Helper()
		require.NoError(t, db.Exec(`INSERT INTO ca_certificates (serial_number, metadata, id, creation_ts, "level") VALUES (?, '{}', ?, '2026-01-01 00:00:00', 0)`, serial, "ca-"+serial).Error)
	}

	insertCertificate("a-ca-current", "ACTIVE", "k1", "engine", true)
	insertCA("a-ca-current")
	insertCertificate("b-ca-superseded", "ACTIVE", "k1", "engine", true) // reissued or deleted CA: no CA points to it
	insertCertificate("c-leaf", "ACTIVE", "k2", "engine", false)
	insertCertificate("d-leaf-revoked", "REVOKED", "k3", "engine", false)
	insertCertificate("e-leaf-external", "ACTIVE", "", "", false)

	page, err := store.SelectKeyUsersAfter(ctx, "", 2)
	require.NoError(t, err)
	require.Equal(t, []models.CertificateKeyRef{
		{SerialNumber: "a-ca-current", KeyID: "k1", EngineID: "engine"},
		{SerialNumber: "c-leaf", KeyID: "k2", EngineID: "engine"},
	}, page)

	page, err = store.SelectKeyUsersAfter(ctx, "c-leaf", 2)
	require.NoError(t, err)
	require.Equal(t, []models.CertificateKeyRef{
		{SerialNumber: "d-leaf-revoked", KeyID: "k3", EngineID: "engine"},
	}, page)

	page, err = store.SelectKeyUsersAfter(ctx, "d-leaf-revoked", 2)
	require.NoError(t, err)
	require.Empty(t, page)

	t.Run("pages in byte order, like the KMS reconciliation ranges", func(t *testing.T) {
		// A locale collation ignores punctuation and would put "f-~" before "f-a".
		insertCertificate("f-~", "ACTIVE", "k4", "engine", false)
		insertCertificate("f-a", "ACTIVE", "k4", "engine", false)

		page, err := store.SelectKeyUsersAfter(ctx, "f-", 10)
		require.NoError(t, err)
		require.Equal(t, []models.CertificateKeyRef{
			{SerialNumber: "f-a", KeyID: "k4", EngineID: "engine"},
			{SerialNumber: "f-~", KeyID: "k4", EngineID: "engine"},
		}, page)
	})
}
