package iotaws

import "github.com/lamassuiot/lamassuiot/v2/core/config"

type AWSIoTConnectorConfig struct {
	config.BaseConfig `mapstructure:",squash"`

	DMSManagerClient struct {
		config.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"dms_manager_client"`

	DevManagerClient struct {
		config.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	CAClient struct {
		config.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	ConnectorID  string              `mapstructure:"connector_id"`
	AWSSDKConfig config.AWSSDKConfig `mapstructure:"aws_config"`
}
