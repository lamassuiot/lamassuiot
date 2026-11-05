package fsstorage

import (
	"sync"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
)

var (
	fsStorageBuildersMu sync.RWMutex
	fsStorageBuilders   = make(map[config.FSStorageProvider]func(*logrus.Entry, config.FSStorageConfig) (*blob.Bucket, error))
)

func RegisterFSStorageEngine(name config.FSStorageProvider, builder func(*logrus.Entry, config.FSStorageConfig) (*blob.Bucket, error)) {
	fsStorageBuildersMu.Lock()
	defer fsStorageBuildersMu.Unlock()

	fsStorageBuilders[name] = builder
}

func GetEngineBuilder(name config.FSStorageProvider) func(*logrus.Entry, config.FSStorageConfig) (*blob.Bucket, error) {
	fsStorageBuildersMu.RLock()
	defer fsStorageBuildersMu.RUnlock()

	return fsStorageBuilders[name]
}
