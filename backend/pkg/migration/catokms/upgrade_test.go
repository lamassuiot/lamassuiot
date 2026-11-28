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

// lastKMSMigrationOf38 is the version of the kms schema that Lamassu 3.8 ships.
const lastKMSMigrationOf38 = int64(20251031174938)

// A chart that runs this tool before migrating any schema hands it the kms schema of 3.8, which has no digest. The tool
// registers the keys there, and the kms migration that runs afterwards computes their digest.
func TestMigrateWithConfigRunsBeforeTheKMSSchemaIsMigrated(t *testing.T) {
	cfg, suite := postgrestest.BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	ctx := context.Background()
	logger := helpers.SetupLogger(cconfig.Info, "Test", "ca-to-kms")
	kmsDB, caDB := suite.DB[postgres.KMS_SCHEMA], suite.DB[postgres.CA_SCHEMA]
	_, err := postgres.NewMigrator(logger, kmsDB).Goose.UpTo(ctx, lastKMSMigrationOf38)
	require.NoError(t, err)
	_, err = postgres.NewMigrator(logger, caDB).Goose.UpTo(ctx, lastCAMigrationOf38)
	require.NoError(t, err)

	insertCA := func(id string, key *ecdsa.PrivateKey, ski string) {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(len(id)) + time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: id},
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
			VALUES (?, '{}', ?, ?, 0, 'ACTIVE', ?, 'ECDSA', 256, 'HIGH', ?, '', '', '', '', '',
			now(), now() + interval '1 day', '0001-01-01', 'Unspecified', 'IMPORTED_WITH_KEY', 'e1', ?, true)`,
			id, id, id, certificate, id, ski).Error)
		require.NoError(t, caDB.Exec(`INSERT INTO ca_certificates (id, serial_number) VALUES (?, ?)`, id, id).Error)
	}
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	}

	// pre-kms: imported before the KMS, its engine holds the key under its SKI and the KMS has no row
	preKMS := newKey()
	insertCA("pre-kms", preKMS, "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11")
	// shares-key: another certificate of the same key, with another SKI: the key is registered once
	insertCA("shares-key", preKMS, "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22")
	// since-3.7: imported with its key in 3.8, so the KMS stores it under its digest, with an SKI that is not the digest
	since37 := newKey()
	insertCA("since-3.7", since37, "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33")
	require.NoError(t, kmsDB.Exec(`INSERT INTO kms_keys (key_id, engine_id, name, algorithm, size, public_key, has_private_key, creation_ts, metadata)
		VALUES (?, 'e1', 'since-3.7', 'ECDSA', 256, ?, true, now(), '{}')`, keyIDFromPub(t, since37.Public()), pubKeyB64PEM(t, since37.Public())).Error)

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
	require.Equal(t, Result{Inserted: 1, Skipped: 2}, result, "pre-kms registered under its SKI; shares-key and since-3.7 found by their public key")

	result, err = MigrateWithConfig(ctx, logger, storageConf, false)
	require.NoError(t, err)
	require.Equal(t, Result{Skipped: 3}, result, "a second run on the same schema registers nothing")

	// the kms migration computes the digest of what the tool registered and finds no duplicate to stop on
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))
	var keys []struct{ KeyID, Digest string }
	require.NoError(t, kmsDB.Raw(`SELECT key_id, digest FROM kms_keys`).Scan(&keys).Error)
	require.ElementsMatch(t, []struct{ KeyID, Digest string }{
		{"aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11", keyIDFromPub(t, preKMS.Public())},
		{keyIDFromPub(t, since37.Public()), keyIDFromPub(t, since37.Public())},
	}, keys)

	// and the tool still reads the migrated schema
	result, err = MigrateWithConfig(ctx, logger, storageConf, false)
	require.NoError(t, err)
	require.Equal(t, Result{Skipped: 3}, result)
}
