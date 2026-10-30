package ca

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
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
func filesystemKeyPath(t *testing.T, name string) string {
	t.Helper()
	for _, engine := range serverTest.CryptoEngines.Config.CryptoEngines {
		if engine.ID == defaultEngine {
			return filepath.Join(engine.Config["storage_directory"].(string), name)
		}
	}
	t.Fatalf("no %s crypto engine", defaultEngine)
	return ""
}

// normalizeKeyNames runs what starting the KMS with crypto_engines.migrate_keys_format does.
func normalizeKeyNames(t *testing.T) int {
	t.Helper()
	renamed, err := assemblers.NormalizeKMSKeyNames(context.Background(), config.KMSConfig{
		Logs:               cconfig.Logging{Level: cconfig.Info},
		Storage:            serverTest.Storage.Config,
		CryptoEngineConfig: serverTest.CryptoEngines.Config,
	})
	require.NoError(t, err)
	return renamed
}

// A CA imported with its key before the KMS: the crypto engine renamed its key to the certificate's
// SKI and ca-to-kms-migration registered it under that name, while the CA records the key's digest.
// Normalizing the key names makes the CA work through its whole life with the filesystem crypto engine.
func TestKeyOfACAImportedBeforeTheKMSIsRenamedToItsDigest(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK
	caCert, caKey := opensslCA(t)
	profile := newBindingsProfile(t)

	ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: caKey, CACertificate: (*models.X509Certificate)(caCert)})
	require.NoError(t, err)
	require.Equal(t, opensslCAKeyID, ca.Certificate.KeyID)

	// The key as an upgrade from before the KMS leaves it: in the engine and in the KMS under the SKI,
	// bound to the CA certificate.
	require.NoError(t, kmsSchema(t).Exec(`UPDATE kms_keys SET key_id = ? WHERE key_id = ?`, opensslCASKI, opensslCAKeyID).Error)
	require.NoError(t, os.Rename(filesystemKeyPath(t, opensslCAKeyID), filesystemKeyPath(t, opensslCASKI)))
	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&ca.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound, "precondition: the CA cannot reach its key")

	require.Equal(t, 1, normalizeKeyNames(t))
	require.Equal(t, 0, normalizeKeyNames(t), "running it again changes nothing")

	require.FileExists(t, filesystemKeyPath(t, opensslCAKeyID))
	require.NoFileExists(t, filesystemKeyPath(t, opensslCASKI))
	key, err := serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: opensslCASKI})
	require.NoError(t, err, "the old name still finds the key, as an alias")
	require.Equal(t, opensslCAKeyID, key.KeyID)
	require.Equal(t, []string{ca.Certificate.SerialNumber}, boundSerials(t, &ca.Certificate), "the binding follows the key")

	requireIssues(t, ca.ID, profile.ID, caCert)
	reissued, err := caSDK.ReissueCA(ctx, services.ReissueCAInput{CAID: ca.ID})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{ca.Certificate.SerialNumber, reissued.Certificate.SerialNumber}, boundSerials(t, &reissued.Certificate))
	requireIssues(t, ca.ID, profile.ID, (*x509.Certificate)(reissued.Certificate.Certificate))

	revokeCA(t, serverTest.CA.Service, ca.ID)
	require.NoError(t, caSDK.DeleteCA(ctx, services.DeleteCAInput{CAID: ca.ID}))
	_, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: keyURI(&ca.Certificate)})
	require.ErrorIs(t, err, errs.ErrKeyNotFound)
	require.NoFileExists(t, filesystemKeyPath(t, opensslCAKeyID), "the engine copy is deleted with the key")
}
