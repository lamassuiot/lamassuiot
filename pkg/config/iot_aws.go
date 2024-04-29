package config

type IotAWS struct {
	Logs               BaseConfigLogging `mapstructure:"logs"`
	SubscriberEventBus EventBusEngine    `mapstructure:"subscriber_event_bus"`

	DMSManagerClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"dms_manager_client"`

	DevManagerClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	CAClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	ConnectorID  string       `mapstructure:"connector_id"`
	AWSSDKConfig AWSSDKConfig `mapstructure:"aws_config"`
}
