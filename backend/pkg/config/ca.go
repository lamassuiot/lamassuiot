package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type CAConfig struct {
	OtelConfig               cconfig.OTELConfig             `mapstructure:"otel"`
	OpenAPI                  cconfig.OpenAPIConfig          `mapstructure:"openapi"`
	Logs                     cconfig.Logging                `mapstructure:"logs"`
	Server                   cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus        cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage                  cconfig.PluggableStorageEngine `mapstructure:"storage"`
	KMSClient                KMSClient                      `mapstructure:"kms_client"`
	AuthzClient              AuthzClient                    `mapstructure:"authz_client"`
	CertificateMonitoringJob cconfig.MonitoringJob          `mapstructure:"certificate_monitoring_job"`
	// KMSBindingsReconcileJob repairs the KMS key bindings of the certificates. It also runs once at
	// startup.
	KMSBindingsReconcileJob cconfig.MonitoringJob `mapstructure:"kms_bindings_reconcile_job"`
	VAServerDomains         []string              `mapstructure:"va_server_domains"`
	AllowCascadeDelete      bool                  `mapstructure:"allow_cascade_delete"`
}
