package keystore

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/keyvaultkv2"
)

func setupVaultKeyProvider() keystoreTestProvider {
	// Create a new instance of GoCryptoEngine
	return keystoreTestProvider{
		Setup: func() (KeyStore, func(), error) {
			log := helpers.SetupLogger(config.Info, "CA TestCase", "Engine")

			teardown, vaultConfig, _, err := keyvaultkv2_test.RunHashicorpVaultDocker()
			if err != nil {
				return nil, nil, fmt.Errorf("could not start vault: %s", err)
			}

			cfgVault := config.HashicorpVaultCryptoEngineConfig{
				HashicorpVaultSDK: *vaultConfig,
				ID:                "dockertest-hcpvault-kvv2",
				Metadata:          make(map[string]interface{}),
			}

			engine, err := NewVaultKV2Engine(log, cfgVault)
			if err != nil {
				log.Warnf("Skipping vault engine with id %s: %s", cfgVault.ID, err)
			}

			return engine, func() {
				teardown()
			}, nil
		},
	}
}
