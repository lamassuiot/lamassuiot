package keystore

import (
	"os"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
)

func setupFilesystemKeyProvider() keystoreTestProvider {
	return keystoreTestProvider{
		Setup: func() (KeyStore, func(), error) {
			// Create a temporary directory for testing
			tempDir := os.TempDir() + "/testing"

			// Create a new instance of GoCryptoEngine
			log := helpers.SetupLogger(config.Info, "CA TestCase", "Golang Engine")

			fileCfg := config.GolangFilesystemEngineConfig{
				ID:               "testing-value-storage",
				StorageDirectory: "testing",
			}

			keyStorage := NewFilesystemKeyStorage(log, fileCfg)

			return keyStorage, func() {
				// Remove the temporary directory
				os.RemoveAll(tempDir)
			}, nil

		},
	}
}
