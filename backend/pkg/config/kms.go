package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type KMSConfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus  cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	CryptoEngineConfig CryptoEngines                  `mapstructure:"crypto_engines"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
}

type CryptoEngines struct {
	LogLevel          cconfig.LogLevel             `mapstructure:"log_level"`
	DefaultEngine     string                       `mapstructure:"default_id"`
	MigrateKeysFormat bool                         `mapstructure:"migrate_keys_format"`
	CryptoEngines     []cconfig.CryptoEngineConfig `mapstructure:"engines"`
}
