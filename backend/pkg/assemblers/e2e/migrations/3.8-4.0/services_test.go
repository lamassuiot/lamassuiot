package migrations38to40

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// cryptoEngines is the crypto engine config of the KMS: the filesystem engine on the directory phase 1 wrote, with the
// renaming of keys at start that an upgrade turns on.
func (e *env) cryptoEngines() config.CryptoEngines {
	return config.CryptoEngines{
		LogLevel:          cconfig.Info,
		DefaultEngine:     engineID,
		MigrateKeysFormat: true,
		CryptoEngines: []cconfig.CryptoEngineConfig{{
			ID:       engineID,
			Type:     cconfig.FilesystemProvider,
			Metadata: map[string]any{},
			Config:   map[string]any{"storage_directory": e.engineDir},
		}},
	}
}

func (e *env) kmsConfig() config.KMSConfig {
	return config.KMSConfig{
		Logs:               cconfig.Logging{Level: cconfig.Info},
		Storage:            e.storageConf(),
		CryptoEngineConfig: e.cryptoEngines(),
	}
}

// startServices is phase 3: KMS, CA and VA on the migrated database. The services do not migrate schemas, and the
// test never calls the server's BeforeEach, which would empty the database.
func (e *env) startServices() *tests.TestServer {
	e.t.Helper()
	srv, err := tests.AssembleServices(
		&tests.TestStorageEngineConfig{Config: e.storageConf()},
		&tests.TestEventBusConfig{Config: cconfig.EventBusEngine{Enabled: false}},
		&tests.TestCryptoEngineConfig{Config: e.cryptoEngines()},
		nil, []tests.Service{tests.CA, tests.VA}, false, false)
	require.NoError(e.t, err)
	e.t.Cleanup(srv.AfterSuite)
	return srv
}

func newProfile(t *testing.T, srv *tests.TestServer) *models.IssuanceProfile {
	t.Helper()
	profile, err := srv.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: "upgrade 3.8-4.0", Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)
	return profile
}

// initCRL creates the CRL settings of a CA and issues its first CRL. The VA does it when it hears of a new CA on the
// event bus, which these tests leave off.
func initCRL(t *testing.T, srv *tests.TestServer, caID string) {
	t.Helper()
	_, err := srv.VA.CRLService.InitCRLSettings(context.Background(), caID)
	require.NoError(t, err)
}

// importCA imports a fixture CA with its key through the CA API, as an operator of v4 does.
func (e *env) importCA(srv *tests.TestServer, name string, profile *models.IssuanceProfile) *models.CACertificate {
	e.t.Helper()
	fx := e.fx[name]
	ca, err := srv.CA.HttpCASDK.ImportCA(context.Background(), services.ImportCAInput{
		ProfileID:     profile.ID,
		CACertificate: (*models.X509Certificate)(fx.Cert),
		Key:           fx.Key,
		EngineID:      engineID,
	})
	require.NoError(e.t, err, "import CA %s", name)
	e.caID[name] = ca.ID
	initCRL(e.t, srv, ca.ID)
	return ca
}

// createRootF creates CA F with Lamassu v4, which generates its key in the KMS.
func (e *env) createRootF(srv *tests.TestServer, profile *models.IssuanceProfile) *models.CACertificate {
	e.t.Helper()
	ca, err := srv.CA.HttpCASDK.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "Upgrade F Lamassu 4.0"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(48 * time.Hour)},
		ProfileID:    profile.ID,
		EngineID:     engineID,
	})
	require.NoError(e.t, err)
	e.caID["F"] = ca.ID
	initCRL(e.t, srv, ca.ID)
	return ca
}

// keyURI is the PKCS#11 URI that names a key in the filesystem engine.
func keyURI(keyID string) string {
	return "pkcs11:token-id=" + engineID + ";id=" + keyID + ";type=private"
}
