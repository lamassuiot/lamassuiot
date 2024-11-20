//go:build experimental || couchdb

package builder

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/test/subsystems"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestBuildStorageEngineCouchDB(t *testing.T) {
	builder := subsystems.GetSubsystemBuilder[subsystems.StorageSubsystem](subsystems.CouchDB)
	backend, err := builder.Run()
	if err != nil {
		t.Fatalf("could not run storage subsystem: %s", err)
	}

	t.Cleanup(func() { backend.AfterSuite() })
	logger := log.WithField("test", "BuildStorageEngine_CouchDB")

	conf := backend.Config.(config.PluggableStorageEngine)

	// Call the BuildStorageEngine function
	storageEngine, err := BuildStorageEngine(logger, conf)

	// Verify the result
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	assert.Equal(t, storageEngine.GetProvider(), config.CouchDB)
}
