package pkcs11

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.PKCS11Provider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := config.DecodeStruct[config.PKCS11EngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewPKCS11Engine(logger, ceConfig)
	})
}
