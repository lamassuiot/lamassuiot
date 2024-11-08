package pkcs11

import (
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/crypto/pkcs11/config"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(cconfig.PKCS11Provider, func(logger *log.Entry, conf cconfig.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := cconfig.DecodeStruct[config.PKCS11EngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewPKCS11Engine(logger, ceConfig)
	})
}