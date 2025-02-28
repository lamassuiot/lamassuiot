package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type VAconfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	SubscriberEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	PublisherEventBus  cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
	FilesystemStorage  cconfig.FSStorageConfig        `mapstructure:"filesystem_storage"`
	CRLMonitoringJob   cconfig.MonitoringJob          `mapstructure:"crl_monitoring_job"`
	CAClient           CAClient                       `mapstructure:"ca_client"`
}

type CAClient struct {
	cconfig.HTTPClient `mapstructure:",squash"`
}
