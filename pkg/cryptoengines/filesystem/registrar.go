package filesystem

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.FilesystemProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := config.DecodeStruct[config.FilesystemEngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewFilesystemPEMEngine(logger, ceConfig)
	})
}
