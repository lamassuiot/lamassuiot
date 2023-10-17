package config

type IotAutomation struct {
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

	Providers struct {
		AWS []struct {
			ConnectorID  string       `mapstructure:"connector_id"`
			AWSSDKConfig AWSSDKConfig `mapstructure:",squash"`
		} `mapstructure:"aws_iot"`
	} `mapstructure:"automation_providers"`

	LamassuInstanceURL string `mapstructure:"lamassu_url"`
}
