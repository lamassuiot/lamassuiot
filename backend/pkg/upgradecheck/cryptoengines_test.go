package upgradecheck

import (
	"context"
	"testing"

	bconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestCryptoEnginesCheck(t *testing.T) {
	env := &Env{}
	check := CryptoEnginesCheck(testLogger, bconfig.CryptoEngines{
		DefaultEngine: "fs",
		CryptoEngines: []cconfig.CryptoEngineConfig{
			{ID: "fs", Type: cconfig.FilesystemProvider, Config: map[string]any{"storage_directory": t.TempDir()}},
			{ID: "bad", Type: "nope"},
		},
	})

	problems, err := check.Run(context.Background(), env)
	require.NoError(t, err)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], "crypto engine bad (nope) cannot start")
	require.Len(t, env.Engines, 1)
	require.Contains(t, env.Engines, "fs")
}

func TestCryptoEnginesCheckWithoutEngines(t *testing.T) {
	env := &Env{}
	problems, err := CryptoEnginesCheck(testLogger, bconfig.CryptoEngines{}).Run(context.Background(), env)
	require.NoError(t, err)
	require.Empty(t, problems)
	require.Empty(t, env.Engines)
}
