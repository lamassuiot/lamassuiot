package builder

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	couchdb_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/couchdb"
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

func TestBuildStorageEngineCouchDB(t *testing.T) {
	cleanfunc, cdbconfig, err := couchdb_test.RunCouchDBDocker()
	if err != nil {
		t.Fatalf("could not run couchdb docker container: %s", err)
	}
	t.Cleanup(func() { _ = cleanfunc() })

	logger := log.WithField("test", "BuildStorageEngine_CouchDB")
	conf := config.PluggableStorageEngine{
		Provider: config.CouchDB,
		CouchDB:  *cdbconfig,
	}

	// Call the BuildStorageEngine function
	storageEngine, err := BuildStorageEngine(logger, conf)

	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, ok := storageEngine.(*couchdb.CouchDBStorageEngine)
	if !ok {
		t.Error("expected storage engine of type *couchdb.StorageEngine")
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
