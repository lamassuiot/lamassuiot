package fsstorage

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
)

var fsStorageBuilders = make(map[config.FSStorageProvider]func(*logrus.Entry, config.FSStorageConfig) (*blob.Bucket, error))

func RegisterFSStorageEngine(name config.FSStorageProvider, builder func(*logrus.Entry, config.FSStorageConfig) (*blob.Bucket, error)) {
	fsStorageBuilders[name] = builder
}

func GetEngineBuilder(name config.FSStorageProvider) func(*logrus.Entry, config.FSStorageConfig) (*blob.Bucket, error) {
	return fsStorageBuilders[name]
}
