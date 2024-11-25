package pkcs11

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(cconfig.PKCS11Provider, func(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {

		ceConfig, err := cconfig.CryptoEngineConfigAdapter[PKCS11Config]{}.Marshal(conf)
		if err != nil {
			return nil, err
		}

		return NewPKCS11Engine(logger, *ceConfig)
	})
}
