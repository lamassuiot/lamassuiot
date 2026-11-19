package upgradecheck

import (
	"bytes"
	"context"
	"testing"

	bconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/stretchr/testify/require"
)

func kmsConfig(t *testing.T, pg *lconfig.PostgresPSEConfig) bconfig.KMSConfig {
	return bconfig.KMSConfig{
		Storage: cconfig.PluggableStorageEngine{
			Provider: cconfig.Postgres,
			Config: map[string]any{
				"hostname": pg.Hostname,
				"port":     pg.Port,
				"username": pg.Username,
				"password": string(pg.Password),
			},
		},
		CryptoEngineConfig: bconfig.CryptoEngines{
			DefaultEngine: "fs",
			CryptoEngines: []cconfig.CryptoEngineConfig{
				{ID: "fs", Type: cconfig.FilesystemProvider, Config: map[string]any{"storage_directory": t.TempDir()}},
			},
		},
	}
}

func runWithConfig(t *testing.T, conf bconfig.KMSConfig) (int, string) {
	var out bytes.Buffer
	code := RunWithConfig(context.Background(), testLogger, conf, &out)
	return code, out.String()
}

func TestRunWithConfigClean(t *testing.T) {
	f := newFixture(t)
	vaScenarios[0].setup(f)

	code, out := runWithConfig(t, kmsConfig(t, f.cfg))
	require.Equal(t, 0, code, out)
	require.Contains(t, out, "Covered migrations: va/20261104121000_va_role_signer_certificate, va/20261111120000_crl_settings")
}

func TestRunWithConfigFresh38WithoutRoles(t *testing.T) {
	f := newFixture(t)

	code, out := runWithConfig(t, kmsConfig(t, f.cfg))
	require.Equal(t, 0, code, out)
}

func TestRunWithConfigReportsProblems(t *testing.T) {
	f := newFixture(t)
	orphan := f.cert("c-orph", "fs")
	f.role(orphan, orphan)
	f.cert("c-x", "fs")
	f.ca("legacy-"+orphan, "c-x", "2020-01-01")

	code, out := runWithConfig(t, kmsConfig(t, f.cfg))
	require.Equal(t, 1, code, out)
	require.Contains(t, out, "CA legacy-"+orphan+" has the id reserved for the archived settings of this role")
}

func TestRunWithConfigRefusesMigratedDatabase(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, migrateV4(t, f.cfg))

	code, out := runWithConfig(t, kmsConfig(t, f.cfg))
	require.Equal(t, 2, code, out)
	require.Contains(t, out, "3.8")
}

func TestRunWithConfigUnreachableDatabase(t *testing.T) {
	code, out := runWithConfig(t, kmsConfig(t, &lconfig.PostgresPSEConfig{Hostname: "127.0.0.1", Port: 1, Username: "u", Password: "p"}))
	require.Equal(t, 2, code, out)
}

func TestRunWithConfigUnsupportedStorage(t *testing.T) {
	conf := kmsConfig(t, &lconfig.PostgresPSEConfig{})
	conf.Storage.Provider = cconfig.CouchDB
	code, out := runWithConfig(t, conf)
	require.Equal(t, 2, code, out)
	require.Contains(t, out, "postgres")
}
