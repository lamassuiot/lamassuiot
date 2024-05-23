package builder

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	log "github.com/sirupsen/logrus"
)

func TestBuildStorageEnginePostgres(t *testing.T) {
	logger := log.WithField("test", "BuildStorageEngine_Postgres")
	conf := config.PluggableStorageEngine{
		Provider: config.Postgres,
		Postgres: config.PostgresPSEConfig{
			// Set Postgres configuration here
		},
	}

	// Call the BuildStorageEngine function
	storageEngine, err := BuildStorageEngine(logger, conf)

	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, ok := storageEngine.(*postgres.PostgresStorageEngine)
	if !ok {
		t.Error("expected storage engine of type *postgres.StorageEngine")
	}
}

func TestBuildStorageEngineInvalidProvider(t *testing.T) {
	logger := log.WithField("test", "BuildStorageEngine_InvalidProvider")
	conf := config.PluggableStorageEngine{
		Provider: "invalid_provider",
	}

	// Call the BuildStorageEngine function
	_, err := BuildStorageEngine(logger, conf)

	// Verify the result
	if err == nil {
		t.Error("expected an error, but got nil")
	}

	if err.Error() != "no storage engine of type invalid_provider" {
		t.Errorf("unexpected error: %s", err)
	}
}
