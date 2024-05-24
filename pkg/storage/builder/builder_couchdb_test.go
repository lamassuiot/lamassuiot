//go:build experimental
// +build experimental

package builder

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/couchdb"
	couchdb_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/couchdb"
	log "github.com/sirupsen/logrus"
)

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
