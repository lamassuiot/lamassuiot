package builder

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	log "github.com/sirupsen/logrus"
)

func BuildStorageEngine(logger *log.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {
	builder := storage.GetEngineBuilder(conf.Provider)
	if builder == nil {
		return nil, fmt.Errorf("no storage engine of type %s", conf.Provider)
	}

	return builder(logger, conf)
}
