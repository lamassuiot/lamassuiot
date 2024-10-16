package builder

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/filesystem"
	log "github.com/sirupsen/logrus"
)

func TestBuildStorageEnginePostgres(t *testing.T) {
	logger := log.WithField("test", "BuildCryptoEngine_Filesystem")

	cfg := map[string]interface{}{
		"StorageDirectory": "filepath",
	}

	conf := config.CryptoEngine{
		ID:     "local",
		Type:   config.GolangProvider,
		Config: cfg,
	}

	// Call the BuildStorageEngine function
	engine, err := BuildCryptoEngine(logger, conf)

	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, ok := engine.(*filesystem.GoCryptoEngine)
	if !ok {
		t.Error("expected storage engine of type *filesystem.GoCryptoEngine")
	}
}

func TestBuildStorageEngineInvalidProvider(t *testing.T) {
	logger := log.WithField("test", "BuildCryptoEngine_InvalidProvider")

	cfg := map[string]interface{}{
		"StorageDirectory": "filepath",
	}

	conf := config.CryptoEngine{
		ID:     "local",
		Type:   config.CryptoEngineProvider("invalid_provider"),
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
