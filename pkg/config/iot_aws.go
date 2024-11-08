package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
)

type IotAWS struct {
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

	ConnectorID               string               `mapstructure:"connector_id"`
	AWSSDKConfig              cconfig.AWSSDKConfig `mapstructure:"aws_config"`
	AWSBidirectionalQueueName string               `mapstructure:"aws_bidirectional_queue_name"`
}

var IotAWSDefaults = IotAWS{
	AWSBidirectionalQueueName: "Lamassu-IoT-SYNC-EventBridgeOutput6A8BBEEC-LaYbNuW753SC",
}
