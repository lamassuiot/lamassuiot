package config

import cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"

type DMSconfig struct {
	Logs              BaseConfigLogging              `mapstructure:"logs"`
	Server            HttpServer                     `mapstructure:"server"`
	PublisherEventBus EventBusEngine                 `mapstructure:"publisher_event_bus"`
	Storage           cconfig.PluggableStorageEngine `mapstructure:"storage"`

	CAClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	DevManagerClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	DownstreamCertificateFile string `mapstructure:"downstream_cert_file"`
}
