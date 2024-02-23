package vaultengine

import "github.com/lamassuiot/lamassuiot/v2/core/config"

type HashicorpVaultCryptoEngineConfig struct {
	config.HashicorpVaultSDK `mapstructure:",squash"`
	ID                string                 `mapstructure:"id"`
	Metadata          map[string]interface{} `mapstructure:"metadata"`
}
