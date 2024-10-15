package vaultkv2

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func Register() {
	cryptoengines.RegisterCryptoEngine(config.HashicorpVaultProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {
		var ceConfig config.HashicorpVaultCryptoEngineConfig
		config.DecodeStruct(conf.Config, &ceConfig)
		return NewVaultKV2Engine(logger, ceConfig)
	})
}
