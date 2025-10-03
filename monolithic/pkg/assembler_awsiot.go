//go:build !noaws
// +build !noaws

package pkg

import (
	awsiotconnector "github.com/lamassuiot/lamassuiot/connectors/awsiot/v3/pkg"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func AssembleAWSIoT(conf MonolithicConfig, caSDKBuilder func(serviceID string, src string) services.CAService, dmsMngrSDKBuilder func(serviceID string, src string) services.DMSManagerService, deviceMngrSDKBuilder func(serviceID string, src string) services.DeviceManagerService) error {
	_, err := awsiotconnector.AssembleAWSIoTManagerService(awsiotconnector.ConnectorServiceConfig{
		Logs: cconfig.Logging{
			Level: conf.Logs.Level,
		},
		SubscriberEventBus:    conf.SubscriberEventBus,
		SubscriberDLQEventBus: conf.SubscriberDLQEventBus,
		ConnectorID:           conf.AWSIoTManager.ConnectorID,
		AWSSDKConfig:          conf.AWSIoTManager.AWSSDKConfig,
	}, caSDKBuilder("AWS IoT Connector", awsiotconnector.AWSIoTSource(conf.AWSIoTManager.ConnectorID)),
		dmsMngrSDKBuilder("AWS IoT Connector", awsiotconnector.AWSIoTSource(conf.AWSIoTManager.ConnectorID)),
		deviceMngrSDKBuilder("AWS IoT Connector", awsiotconnector.AWSIoTSource(conf.AWSIoTManager.ConnectorID)))
	return err
}
