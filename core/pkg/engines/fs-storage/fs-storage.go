package cryptoengines

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
)

type FSStorageEngine blob.Bucket

var fsStorageBuilders = make(map[config.CryptoEngineProvider]func(*logrus.Entry, config.FSStorageConfig) (blob.Bucket, error))

func RegisterFSStorageEngine(name config.CryptoEngineProvider, builder func(*logrus.Entry, config.FSStorageConfig) (blob.Bucket, error)) {
	fsStorageBuilders[name] = builder
}

func GetEngineBuilder(name config.CryptoEngineProvider) func(*logrus.Entry, config.FSStorageConfig) (blob.Bucket, error) {
	return fsStorageBuilders[name]
}
