package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type AsymmetricKMSConfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	SubscriberEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CryptoEngineConfig CryptoEngines                  `mapstructure:"crypto_engines"`
}

type CryptoEngines struct {
	LogLevel      cconfig.LogLevel             `mapstructure:"log_level"`
	DefaultEngine string                       `mapstructure:"default_id"`
	CryptoEngines []cconfig.CryptoEngineConfig `mapstructure:"engines"`
}
