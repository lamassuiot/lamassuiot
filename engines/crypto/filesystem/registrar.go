package filesystem

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(cconfig.FilesystemProvider, func(logger *log.Entry, conf cconfig.CryptoEngine[any]) (cryptoengines.CryptoEngine, error) {
		ceConfig, _ := cconfig.DecodeStruct[cconfig.CryptoEngine[FilesystemEngineConfig]](conf)
		return NewFilesystemPEMEngine(logger, ceConfig)
	})
}
