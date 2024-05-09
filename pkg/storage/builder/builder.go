package builder

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	log "github.com/sirupsen/logrus"
)

func BuildStorageEngine(logger *log.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {

	switch conf.Provider {
	case config.Postgres:
		storageEngine, err := postgres.NewStorageEngine(logger, conf.Postgres)
		if err != nil {
			return nil, err
		}
		return storageEngine, err
	case config.CouchDB:
		storageEngine, err := couchdb.NewStorageEngine(logger, conf.CouchDB)
		if err != nil {
			return nil, err
		}
		return storageEngine, err
	default:
		return nil, fmt.Errorf("no storage engine of type %s", conf.Provider)
	}
}
