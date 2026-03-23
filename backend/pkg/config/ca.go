package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

func (c CAConfig) GetOtel() cconfig.OTELConfig          { return c.OtelConfig }
func (c CAConfig) GetLogs() cconfig.Logging             { return c.Logs }
func (c CAConfig) GetServer() cconfig.HttpServer        { return c.Server }
func (c CAConfig) GetPublisher() cconfig.EventBusEngine { return c.PublisherEventBus }

type CAConfig struct {
	OtelConfig               cconfig.OTELConfig             `mapstructure:"otel"`
	Logs                     cconfig.Logging                `mapstructure:"logs"`
	Server                   cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus        cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage                  cconfig.PluggableStorageEngine `mapstructure:"storage"`
	KMSClient                KMSClient                      `mapstructure:"kms_client"`
	CertificateMonitoringJob cconfig.MonitoringJob          `mapstructure:"certificate_monitoring_job"`
	VAServerDomains          []string                       `mapstructure:"va_server_domains"`
	AllowCascadeDelete       bool                           `mapstructure:"allow_cascade_delete"`
}
