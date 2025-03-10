package localfs

import (
	"context"
	"fmt"
	"os"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	fsstorage "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/fs-storage"
	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
)

func Register() {
	fsstorage.RegisterFSStorageEngine(config.LocalFilesystem, func(logger *log.Entry, conf config.FSStorageConfig) (*blob.Bucket, error) {
		engineConfig, _ := config.FSStorageConfigAdapter[FilesystemEngineConfig]{}.Marshal(conf)

		os.MkdirAll(engineConfig.Config.StorageDirectory, os.ModePerm)

		uri := fmt.Sprintf("file://%s?no_tmp_dir=1", engineConfig.Config.StorageDirectory)
		bucket, err := blob.OpenBucket(context.Background(), uri)
		if err != nil {
			return nil, err
		}

		return bucket, nil
	})
}
