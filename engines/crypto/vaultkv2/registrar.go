package vaultkv2

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v3/crypto/vaultkv2/config"

	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(cconfig.HashicorpVaultProvider, func(logger *log.Entry, conf cconfig.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := cconfig.DecodeStruct[config.HashicorpVaultCryptoEngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewVaultKV2Engine(logger, ceConfig)
	})
}
