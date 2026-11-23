package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

func TestLoadConfigPreservesCredentialSchemaNamesContainingDots(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
credentials:
  pki.v2:
    provider: postgres
    database: pki
`), 0600))
	t.Setenv("LAMASSU_CONFIG_FILE", configPath)

	config, err := cconfig.LoadConfig[AuthzConfig](nil)

	require.NoError(t, err)
	require.Contains(t, config.Credentials, "pki.v2")
	require.Equal(t, cconfig.StorageProvider("postgres"), config.Credentials["pki.v2"].Provider)
}
