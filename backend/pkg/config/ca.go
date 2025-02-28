package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type CAConfig struct {
	Logs              cconfig.Logging                `mapstructure:"logs"`
	Server            cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage           cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CryptoMonitoring  cconfig.MonitoringJob          `mapstructure:"crypto_monitoring"`
	VAServerDomains   []string                       `mapstructure:"va_server_domains"`
}
