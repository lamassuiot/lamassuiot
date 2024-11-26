package builder

import (
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3"
	log "github.com/sirupsen/logrus"
)

func TestBuildStorageEnginePostgres(t *testing.T) {
	logger := log.WithField("test", "BuildCryptoEngine_Filesystem")

	cfg := map[string]interface{}{
		"StorageDirectory": "filepath",
	}

	conf := cconfig.CryptoEngineConfig{
		ID:     "local",
		Type:   cconfig.FilesystemProvider,
		Config: cfg,
	}

	// Call the BuildStorageEngine function
	engine, err := BuildCryptoEngine(logger, conf)

	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, ok := engine.(*filesystem.FilesystemCryptoEngine)
	if !ok {
		t.Error("expected storage engine of type *filesystem.GoCryptoEngine")
	}
}

func TestBuildStorageEngineInvalidProvider(t *testing.T) {
	logger := log.WithField("test", "BuildCryptoEngine_InvalidProvider")

	cfg := map[string]interface{}{
		"StorageDirectory": "filepath",
	}

	conf := cconfig.CryptoEngineConfig{
		ID:     "local",
		Type:   cconfig.CryptoEngineProvider("invalid_provider"),
		Config: cfg,
	}

	_, err := BuildCryptoEngine(logger, conf)

	// Verify the result
	if err == nil {
		t.Error("expected an error, but got nil")
	}

	if err.Error() != "no crypto engine of type invalid_provider" {
		t.Errorf("unexpected error: %s", err)
	}
}
