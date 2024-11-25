package filesystem

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.FilesystemProvider, func(logger *log.Entry, conf config.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
		ceConfig, _ := config.CryptoEngineConfigAdapter[FilesystemEngineConfig]{}.Marshal(conf)
		return NewFilesystemPEMEngine(logger, *ceConfig)
	})
}
