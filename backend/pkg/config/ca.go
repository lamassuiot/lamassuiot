package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
)

type CAConfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus  cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CryptoEngineConfig CryptoEngines                  `mapstructure:"crypto_engines"`
	CryptoMonitoring   cconfig.MonitoringJob          `mapstructure:"crypto_monitoring"`
	VAServerDomain     string                         `mapstructure:"va_server_domain"`
}

type CryptoEngines struct {
	LogLevel      cconfig.LogLevel             `mapstructure:"log_level"`
	DefaultEngine string                       `mapstructure:"default_id"`
	CryptoEngines []cconfig.CryptoEngineConfig `mapstructure:"engines"`
}
