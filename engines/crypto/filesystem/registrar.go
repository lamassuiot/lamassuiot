package filesystem

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v3/crypto/filesystem/config"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(cconfig.FilesystemProvider, func(logger *log.Entry, conf cconfig.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := cconfig.DecodeStruct[config.FilesystemEngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewFilesystemPEMEngine(logger, ceConfig)
	})
}
