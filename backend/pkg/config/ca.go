package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type CAConfig struct {
	OpenAPISpecPath          string                         `mapstructure:"openapi_spec_path"`
	Logs                     cconfig.Logging                `mapstructure:"logs"`
	Server                   cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus        cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage                  cconfig.PluggableStorageEngine `mapstructure:"storage"`
	KMSClient                KMSClient                      `mapstructure:"kms_client"`
	CertificateMonitoringJob cconfig.MonitoringJob          `mapstructure:"certificate_monitoring_job"`
	VAServerDomains          []string                       `mapstructure:"va_server_domains"`
	AllowCascadeDelete       bool                           `mapstructure:"allow_cascade_delete"`
}
