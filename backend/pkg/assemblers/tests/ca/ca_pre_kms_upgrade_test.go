package ca

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/migration/catokms"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	pconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// kmsSchema connects to the KMS schema of the test database.
func kmsSchema(t *testing.T) *gorm.DB {
	t.Helper()
	cfg, err := cconfig.DecodeStruct[pconfig.PostgresPSEConfig](serverTest.Storage.Config.Config)
	require.NoError(t, err)
	db, err := postgres.CreatePostgresDBConnection(chelpers.SetupLogger(cconfig.Info, "Test", "KMS schema"), cfg, postgres.KMS_SCHEMA)
	require.NoError(t, err)
	return db
}

// filesystemKeyPath is where the filesystem crypto engine keeps a key.
func filesystemKeyPath(t *testing.T, keyID string) string {
	t.Helper()
	for _, engine := range serverTest.CryptoEngines.Config.CryptoEngines {
		if engine.ID == defaultEngine {
			return filepath.Join(engine.Config["storage_directory"].(string), keyID)
		}
	}
	t.Fatalf("no %s crypto engine", defaultEngine)
	return ""
}

// rerunKMSMigration rolls a KMS migration back and applies it again, as an upgrade would run it.
func rerunKMSMigration(t *testing.T, db *gorm.DB, name string) {
	t.Helper()
	m := postgres.NewMigrator(chelpers.SetupLogger(cconfig.Info, "Test", "Migrations"), db)
	for _, src := range m.Goose.ListSources() {
		if strings.Contains(src.Path, name) {
			_, err := m.Goose.ApplyVersion(context.Background(), src.Version, false)
			require.NoError(t, err)
			_, err = m.Goose.ApplyVersion(context.Background(), src.Version, true)
			require.NoError(t, err)
			return
		}
	}
	t.Fatalf("no KMS migration %s", name)
}

// A CA imported with its key before the KMS existed: the crypto engine renamed its key to the
// certificate's SKI, ca-to-kms-migration registered it under that name, and the CA key_id migration
// recorded the SHA-256 key ID instead. After the upgrade migrations, the CA works through its whole
// life with the filesystem crypto engine, reissued or not.
func TestCAImportedBeforeTheKMSWorksAfterTheUpgrade(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK
	caCert, caKey := opensslCA(t)
	profile := newBindingsProfile(t)

	ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: caKey, CACertificate: (*models.X509Certificate)(caCert)})
	require.NoError(t, err)
	require.Equal(t, opensslCAKeyID, ca.Certificate.KeyID)

	// Leave the key as an installation before the KMS left it: in the engine under the SKI, unknown to
	// the KMS. The CA certificate keeps the key_id the CA migration computed.
	kms := kmsSchema(t)
	require.NoError(t, kms.Exec(`DELETE FROM key_bindings WHERE key_id = ?`, opensslCAKeyID).Error)
	require.NoError(t, kms.Exec(`DELETE FROM kms_keys WHERE key_id = ?`, opensslCAKeyID).Error)
	require.NoError(t, os.Rename(filesystemKeyPath(t, opensslCAKeyID), filesystemKeyPath(t, opensslCASKI)))

	// The upgrade: ca-to-kms-migration registers the key, then the KMS migrations run.
	result, err := catokms.MigrateWithConfig(ctx, chelpers.SetupLogger(cconfig.Info, "Test", "ca-to-kms"), serverTest.Storage.Config, false)
	require.NoError(t, err)
	require.Equal(t, 1, result.Inserted)
	rerunKMSMigration(t, kms, "20261027110200_backfill_certificate_key_bindings")

	stored, err := caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: ca.Certificate.SerialNumber})
	require.NoError(t, err)
	require.Equal(t, opensslCASKI, stored.KeyID, "the certificate records the name its key has in the KMS")
	require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, stored))
	requireIssues(t, ca.ID, profile.ID, caCert)

	reissued, err := caSDK.ReissueCA(ctx, services.ReissueCAInput{CAID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, opensslCASKI, reissued.Certificate.KeyID)
	require.ElementsMatch(t, []string{ca.Certificate.SerialNumber, reissued.Certificate.SerialNumber}, boundSerials(t, &reissued.Certificate))
	requireIssues(t, ca.ID, profile.ID, (*x509.Certificate)(reissued.Certificate.Certificate))

	revokeCA(t, serverTest.CA.Service, ca.ID)
	require.NoError(t, caSDK.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))
	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&reissued.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound)
	require.NoFileExists(t, filesystemKeyPath(t, opensslCASKI), "the engine copy is deleted with the key")
}
