package filesystem

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.GolangProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := config.DecodeStruct[config.GolangEngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewGolangPEMEngine(logger, ceConfig)
	})
}
