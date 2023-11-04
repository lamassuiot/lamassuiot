package config

type IotAWS struct {
	BaseConfig `mapstructure:",squash"`

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

	LamassuInstanceURL string `mapstructure:"lamassu_url"`
}
