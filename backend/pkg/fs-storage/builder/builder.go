package builder

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	fsstorage "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/fs-storage"
	"github.com/lamassuiot/lamassuiot/engines/fs-storage/localfs/v3"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
)

func BuildFSStorageEngine(logger *logrus.Entry, conf config.FSStorageConfig) (*blob.Bucket, error) {
	builder := fsstorage.GetEngineBuilder(config.FSStorageProvider(conf.Type))
	if builder == nil {
		return nil, fmt.Errorf("no crypto engine of type %s", conf.Type)
	}

	return builder(logger, conf)
}

func init() {
	localfs.Register()
}
