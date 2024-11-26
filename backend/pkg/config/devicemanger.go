package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type DeviceManagerConfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus  cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	SubscriberEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CAClient           struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`
}
