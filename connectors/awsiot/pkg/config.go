package pkg

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
)

type ConnectorServiceConfig struct {
	Logs               cconfig.Logging        `mapstructure:"logs"`
	SubscriberEventBus cconfig.EventBusEngine `mapstructure:"subscriber_event_bus"`

	DMSManagerClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"dms_manager_client"`

	DevManagerClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	CAClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	ConnectorID               string            `mapstructure:"connector_id"`
	AWSSDKConfig              laws.AWSSDKConfig `mapstructure:"aws_config"`
	AWSBidirectionalQueueName string            `mapstructure:"aws_bidirectional_queue_name"`
}

var ConnectorServiceConfigDefaults = ConnectorServiceConfig{}
