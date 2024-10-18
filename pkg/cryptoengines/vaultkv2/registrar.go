package vaultkv2

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.HashicorpVaultProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := config.DecodeStruct[config.HashicorpVaultCryptoEngineConfig](conf.Config)
		ceConfig.ID = conf.ID
		ceConfig.Metadata = conf.Metadata

		return NewVaultKV2Engine(logger, ceConfig)
	})
}
