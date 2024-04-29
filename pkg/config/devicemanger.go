package config

type DeviceManagerConfig struct {
	Logs               BaseConfigLogging      `mapstructure:"logs"`
	Server             HttpServer             `mapstructure:"server"`
	PublisherEventBus  EventBusEngine         `mapstructure:"publisher_event_bus"`
	SubscriberEventBus EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Storage            PluggableStorageEngine `mapstructure:"storage"`
	CAClient           struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`
}
