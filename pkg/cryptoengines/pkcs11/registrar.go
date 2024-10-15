package pkcs11

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.PKCS11Provider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {
		var ceConfig config.PKCS11EngineConfig
		config.DecodeStruct(conf.Config, &ceConfig)
		return NewPKCS11Engine(logger, ceConfig)
	})
}
