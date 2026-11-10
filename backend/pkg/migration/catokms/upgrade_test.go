package catokms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	postgrestest "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/require"
)

// lastCAMigrationOf38 is the version of the ca schema that Lamassu 3.8 ships.
const lastCAMigrationOf38 = int64(20260520120000)

// The ca migrations of 4.0 only complete once the keys of the existing CAs are in the KMS, and this tool is
// what registers them, so it has to run on the ca schema of 3.8.
func TestMigrateWithConfigRunsBeforeTheCASchemaIsMigrated(t *testing.T) {
	cfg, suite := postgrestest.BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	ctx := context.Background()
	logger := helpers.SetupLogger(cconfig.Info, "Test", "ca-to-kms")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))
	caDB := suite.DB[postgres.CA_SCHEMA]
	_, err := postgres.NewMigrator(logger, caDB).Goose.UpTo(ctx, lastCAMigrationOf38)
	require.NoError(t, err)

	// a CA of 3.8 whose key the KMS does not hold
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Legacy CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	certificate := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, caDB.Exec(`INSERT INTO certificates
		(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength,
		subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality,
		valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, subject_key_id, is_ca)
		VALUES ('legacy-ca', '{}', 'legacy-ca', 'legacy', 0, 'ACTIVE', ?, 'ECDSA', 256, 'HIGH', 'Legacy CA', '', '', '', '', '',
		now(), now() + interval '1 day', '0001-01-01', 'Unspecified', 'MANAGED', 'e1', ?, true)`,
		certificate, keyIDFromPub(t, key.Public())).Error)
	require.NoError(t, caDB.Exec(`INSERT INTO ca_certificates (id, serial_number) VALUES ('legacy', 'legacy-ca')`).Error)

	storageConf := cconfig.PluggableStorageEngine{
		Provider: cconfig.Postgres,
		Config: map[string]any{
			"hostname": cfg.Hostname,
			"port":     cfg.Port,
			"username": cfg.Username,
			"password": string(cfg.Password),
		},
	}
	result, err := MigrateWithConfig(ctx, logger, storageConf, false)
	require.NoError(t, err)
	require.Equal(t, Result{Inserted: 1}, result)

	// with the key registered, the ca schema migrates to the end
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))

	// and the tool still reads the migrated schema
	result, err = MigrateWithConfig(ctx, logger, storageConf, false)
	require.NoError(t, err)
	require.Equal(t, Result{Skipped: 1}, result)
}
