package migrations38to40

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"uuid"

	bhelpers "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/migration/catokms"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	postgres_test "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type variant string

const (
	variantClean variant = "clean"               // the 3.8 database has never seen ca-to-kms-migration
	variantGhost variant = "ghost-from-3.8-tool" // ca-to-kms-migration of 3.8.x already ran on it
)

// v38Versions are the last migrations of each schema at tag backend/v3.8.1, in migration order. Copied from
// backend/pkg/upgradecheck/v38_test.go, a test file that cannot be imported.
var v38Versions = []struct {
	schema  string
	version int64
}{
	{postgres.KMS_SCHEMA, 20251031174938},
	{postgres.CA_SCHEMA, 20260520120000},
	{postgres.VA_SCHEMA, 1},
}

var testLogger = chelpers.SetupLogger(cconfig.Info, "Test", "upgrade 3.8-4.0")

// env is one variant of the upgrade: its database, its crypto engine directory and its CAs.
type env struct {
	t         *testing.T
	variant   variant
	pg        *lconfig.PostgresPSEConfig
	db        map[string]*gorm.DB // by schema
	engineDir string
	fx        map[string]fixtureCA            // "A" … "E"
	caID      map[string]string               // fixture name -> CA id
	crl38     map[string]*x509.RevocationList // fixture name -> last CRL 3.8 published (A, B, C)
}

// newEnv is phase 0: a Postgres whose kms, ca and va schemas are at their 3.8.1 versions, and an empty engine directory.
func newEnv(t *testing.T, v variant) *env {
	t.Helper()
	cleanup, cfg, err := postgres_test.RunPostgresDocker(map[string]string{postgres.KMS_SCHEMA: "", postgres.CA_SCHEMA: "", postgres.VA_SCHEMA: ""}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleanup() })

	e := &env{t: t, variant: v, pg: cfg, db: map[string]*gorm.DB{}, engineDir: t.TempDir(), fx: map[string]fixtureCA{}, caID: map[string]string{}, crl38: map[string]*x509.RevocationList{}}
	for _, pin := range v38Versions {
		db, err := postgres.CreatePostgresDBConnection(testLogger, *cfg, pin.schema)
		require.NoError(t, err)
		_, err = postgres.NewMigrator(testLogger, db).Goose.UpTo(context.Background(), pin.version)
		require.NoError(t, err, "migrate %s to %d", pin.schema, pin.version)
		e.db[pin.schema] = db
	}
	for _, name := range []string{"A", "B", "C", "D", "E"} {
		e.fx[name] = loadFixture(t, name)
	}
	return e
}

func (e *env) exec(schema, sql string, args ...any) {
	e.t.Helper()
	require.NoError(e.t, e.db[schema].Exec(sql, args...).Error)
}

func keyMeta(fx fixtureCA) (algorithm string, bits int) {
	switch pub := fx.Cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	}
	panic("unsupported key type")
}

// insertCA writes the certificate and CA rows of a fixture as a 3.8.1 database holds them.
func (e *env) insertCA(fx fixtureCA, certType string) {
	e.t.Helper()
	id := uuid.NewV7().String()
	e.caID[fx.Name] = id
	serial := bhelpers.SerialNumberToHexString(fx.Cert.SerialNumber)
	alg, bits := keyMeta(fx)
	e.exec(postgres.CA_SCHEMA, `INSERT INTO certificates
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength,
		subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality,
		issuer_common_name, valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, subject_key_id, authority_key_id, is_ca)
		VALUES (?, '{}', ?, ?, 0, 'ACTIVE', ?, ?, ?, 'HIGH', ?, '', '', '', '', '', ?, ?, ?, '0001-01-01', 'Unspecified', ?, ?, ?, ?, true)`,
		serial, serial, id, certB64PEM(fx.Cert), alg, bits, fx.Cert.Subject.CommonName, fx.Cert.Issuer.CommonName,
		fx.Cert.NotBefore, fx.Cert.NotAfter, certType, engineID, fx.SKI, hex.EncodeToString(fx.Cert.AuthorityKeyId))
	e.exec(postgres.CA_SCHEMA, `INSERT INTO ca_certificates (id, serial_number, creation_ts, level, metadata) VALUES (?, ?, ?, 0, '{}')`,
		id, serial, fx.Cert.NotBefore)
}

// insertKey writes a kms_keys row of the 3.8.1 schema, named keyID.
func (e *env) insertKey(fx fixtureCA, keyID string, metadata map[string]any) {
	e.t.Helper()
	alg, bits := keyMeta(fx)
	meta, err := json.Marshal(metadata)
	require.NoError(e.t, err)
	e.exec(postgres.KMS_SCHEMA, `INSERT INTO kms_keys (key_id, engine_id, name, algorithm, size, public_key, has_private_key, creation_ts, metadata)
		VALUES (?, ?, ?, ?, ?, ?, true, ?, ?::jsonb)`,
		keyID, engineID, fx.Cert.Subject.CommonName, alg, bits, kmsPublicKey(e.t, fx.Cert.PublicKey), fx.Cert.NotBefore, string(meta))
}

func (e *env) writeEngineFile(fx fixtureCA, name string) {
	e.t.Helper()
	require.NoError(e.t, os.WriteFile(filepath.Join(e.engineDir, name), fx.KeyPEM, 0o600))
}

// write38State is phase 1: CAs A, B and C as a 3.8.1 installation holds them.
func (e *env) write38State() {
	e.t.Helper()
	a, b, c := e.fx["A"], e.fx["B"], e.fx["C"]

	// A: imported with its key in 3.8, so the KMS holds it under its digest.
	e.insertCA(a, "IMPORTED_WITH_KEY")
	e.insertKey(a, a.Digest, map[string]any{})
	e.writeEngineFile(a, a.Digest)
	// B: imported before the KMS, so only the engine holds it, under its SKI.
	e.insertCA(b, "IMPORTED_WITH_KEY")
	e.writeEngineFile(b, skiB)
	// C: created by Lamassu 3.8, so its key, its row and its SKI are all named by its digest.
	e.insertCA(c, "MANAGED")
	e.insertKey(c, c.Digest, map[string]any{})
	e.writeEngineFile(c, c.Digest)

	for _, fx := range []fixtureCA{a, b, c} {
		e.exec(postgres.VA_SCHEMA, `INSERT INTO va_role (ca_ski, crl_subject_key_id_signer, crl_validity, crl_refresh_interval,
			crl_regenerate_on_revoke, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
			VALUES (?, ?, '168h0m0s', '166h0m0s', true, 1, now(), now() + interval '7 days')`, fx.SKI, fx.SKI)
		e.crl38[fx.Name] = e.write38CRL(fx) // the CRL number 1 the role above points at
	}

	if e.variant == variantGhost {
		// What ca-to-kms-migration of 3.8.1 inserts: every CA key under its SKI, looked up by that name only. C is found
		// under its own name; A is registered again (the ghost), and B for the first time.
		for _, fx := range []fixtureCA{a, b} {
			serial := bhelpers.SerialNumberToHexString(fx.Cert.SerialNumber)
			e.insertKey(fx, fx.SKI, map[string]any{"lamassu.io/kms/binded-resources": []string{serial}})
		}
	}
}

// migrate applies every v4 migration of a schema. Unlike postgres.MigrateDatabase, which exits the process on a failing
// migration, it fails the test with the migration's error.
func (e *env) migrate(schema string) {
	e.t.Helper()
	_, err := postgres.NewMigrator(testLogger, e.db[schema]).Goose.Up(context.Background())
	require.NoError(e.t, err, "migrate schema %s", schema)
}

// storageConf is the storage config of the services and of ca-to-kms-migration for this database.
func (e *env) storageConf() cconfig.PluggableStorageEngine {
	return cconfig.PluggableStorageEngine{
		LogLevel: cconfig.Info,
		Provider: cconfig.Postgres,
		Config: map[string]any{
			"hostname": e.pg.Hostname,
			"port":     e.pg.Port,
			"username": e.pg.Username,
			"password": string(e.pg.Password),
		},
	}
}

// runTool runs ca-to-kms-migration as an operator does, against the whole database.
func (e *env) runTool() catokms.Result {
	e.t.Helper()
	res, err := catokms.MigrateWithConfig(context.Background(), testLogger, e.storageConf(), false)
	require.NoError(e.t, err)
	return res
}

func (e *env) kmsRowCount() int {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db[postgres.KMS_SCHEMA].Raw(`SELECT count(*) FROM kms_keys`).Scan(&n).Error)
	return int(n)
}

// engineFiles lists the keys the filesystem crypto engine holds, by name.
func (e *env) engineFiles() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.engineDir)
	require.NoError(e.t, err)
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return sortedStrings(names...)
}

func sortedStrings(s ...string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}
