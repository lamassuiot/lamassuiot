package config

type IoTAWSConfig struct {
	BaseConfig `mapstructure:",squash"`
	ID         string `mapstructure:"id"`

	CAClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	AWSSDKConfig AWSSDKConfig `mapstructure:"aws_iot"`
}
