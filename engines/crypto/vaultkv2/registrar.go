package vaultkv2

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	vconfig "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/config"

	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.HashicorpVaultProvider, func(logger *log.Entry, conf config.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {

		ceConfig, err := config.CryptoEngineConfigAdapter[vconfig.HashicorpVaultSDK]{}.Marshal(conf)
		if err != nil {
			return nil, err
		}

		return NewVaultKV2Engine(logger, *ceConfig)
	})
}
