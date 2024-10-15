package filesystem

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.GolangProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {
		var ceConfig config.GolangEngineConfig
		config.DecodeStruct(conf.Config, &ceConfig)
		return NewGolangPEMEngine(logger, ceConfig)
	})
}
