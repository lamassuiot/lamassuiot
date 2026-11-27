package migrations38to40

import (
	"context"
	"database/sql"
	"testing"

	bhelpers "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/migration/catokms"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

// TestUpgrade38To40OfACADeletedIn38 upgrades a CA that 3.8 deleted after the 3.8.x ca-to-kms-migration had registered
// its key a second time: A, imported with its key in 3.8, so stored under its digest, and registered again under its
// OpenSSL SKI (the ghost row). It checks that the upgrade never leaves that ghost alone, so importing the key again
// cannot run into a row whose key the engine does not hold.
//
// DeleteCA of backend/v3.8.1 requires a revoked or expired CA, deletes its ca_certificates row and keeps its
// certificate. It then deletes the key by the SKI of the certificate (deleteCAPrivateKey -> DeleteKeyByID), which
// names the ghost: the engine never held that name, so DeleteKeyByID answers "key not found" and deletes nothing. The
// VA of 3.8.1 does not hear of the deletion, so the va_role of the CA stays. Phase 1 writes that state with SQL, as
// write38State does for the other tests of this package.
func TestUpgrade38To40OfACADeletedIn38(t *testing.T) {
	e := newEnv(t, variantGhost)
	a := e.fx["A"]
	serial := bhelpers.SerialNumberToHexString(a.Cert.SerialNumber)

	// Phase 1: A imported with its key, registered again by the 3.8.x tool, then revoked and deleted, all in 3.8.
	e.insertCA(a, "IMPORTED_WITH_KEY")
	e.insertKey(a, a.Digest, map[string]any{})
	e.writeEngineFile(a, a.Digest)
	e.insertKey(a, a.SKI, map[string]any{"lamassu.io/kms/binded-resources": []string{serial}})
	e.exec(postgres.VA_SCHEMA, `INSERT INTO va_role (ca_ski, crl_subject_key_id_signer, crl_validity, crl_refresh_interval,
		crl_regenerate_on_revoke, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
		VALUES (?, ?, '168h0m0s', '166h0m0s', true, 1, now(), now() + interval '7 days')`, a.SKI, a.SKI)
	e.exec(postgres.CA_SCHEMA, `UPDATE certificates SET status = 'REVOKED', revocation_timestamp = now() WHERE serial_number = ?`, serial)
	e.exec(postgres.CA_SCHEMA, `DELETE FROM ca_certificates WHERE id = ?`, e.caID["A"])
	require.Equal(t, 2, e.kmsRowCount(), "kms_keys rows in 3.8: the digest of A and its ghost")
	require.Equal(t, []string{a.Digest}, e.engineFiles(), "engine files in 3.8")

	// Phase 2: the upgrade, in the production order kms -> ca-to-kms-migration -> ca -> va.
	e.migrate(postgres.KMS_SCHEMA)
	require.Equal(t, catokms.Result{}, e.runTool(), "the tool reads existing CAs only, and A is deleted")
	e.migrate(postgres.CA_SCHEMA)
	e.migrate(postgres.VA_SCHEMA)

	rows := e.kmsRows()
	require.Len(t, rows, 1, "the kms migration removed the ghost")
	e.requireKey(rows, a, a.Digest, []string{a.SKI})
	require.Equal(t, []string{a.Digest}, e.engineFiles(), "the row left is the one the engine holds")
	var certKeyID sql.NullString
	require.NoError(t, e.db[postgres.CA_SCHEMA].Raw(`SELECT key_id FROM certificates WHERE serial_number = ?`, serial).
		Row().Scan(&certKeyID))
	require.Equal(t, a.Digest, certKeyID.String, "the certificate of the deleted CA references the row left")

	// Phase 3: importing the key again into the same engine finds it there: a 409, with no second row or engine file.
	srv := e.startServices()
	_, err := srv.KMS.HttpKMSSDK.ImportKey(context.Background(), services.ImportKeyInput{PrivateKey: a.Key, EngineID: engineID})
	require.ErrorIs(t, err, errs.ErrKeyAlreadyExists)
	require.Equal(t, rows, e.kmsRows(), "the import changes no row")
	require.Equal(t, []string{a.Digest}, e.engineFiles(), "the import writes no engine file")
}
