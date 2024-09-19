package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/handlers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/iot"
	"github.com/sirupsen/logrus"
)

func AssembleAWSIoTManagerService(conf config.IotAWS, caService services.CAService, dmsService services.DMSManagerService, deviceService services.DeviceManagerService) (*iot.AWSCloudConnectorService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "AWS IoT Connector", "Service")
	lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "AWS IoT Connector", "Event Bus")
	lSqsConDiscon := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "AWS IoT Connector", "SQS - Incoming Conn/Disconn Events")
	lSqsShadowUpd := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "AWS IoT Connector", "SQS - Shadow Update Events")

	awsCfg, err := config.GetAwsSdkConfig(conf.AWSSDKConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get aws config: %s", err)
	}

	awsConnectorSvc, err := iot.NewAWSCloudConnectorServiceService(iot.AWSCloudConnectorBuilder{
		Conf:                         *awsCfg,
		Logger:                       lSvc,
		ConnectorID:                  conf.ConnectorID,
		CaSDK:                        caService,
		DmsSDK:                       dmsService,
		DeviceSDK:                    deviceService,
		IncomingSQSIoTEventQueueName: conf.SQSIncomingEventQueueName,
	})
	if err != nil {
		logrus.Fatal(err)
	}

	handler := handlers.NewAWSIoTEventHandler(lMessaging, awsConnectorSvc)
	subHandler, err := eventbus.NewEventBusSubscriptionHandler(conf.SubscriberEventBus, "aws-connector", lMessaging, *handler, "#-aws-connector", "#")
	if err != nil {
		lMessaging.Errorf("could not generate Event Bus Subscription Handler: %s", err)
	}

	err = subHandler.RunAsync()
	if err != nil {
		lMessaging.Errorf("could not run Event Bus Subscription Handler: %s", err)
		return nil, err
	}

	lSqsConDiscon.Infof("starting Connect/Disconnect Thing Event Bus Subscription Handler")
	connectDisconnectThingMessageHandler := handlers.NewAWSIoTThingConnectionDisconnectionEventHandler(lSqsConDiscon, awsConnectorSvc)
	connectDisconnectThingSubHandler, err := eventbus.NewEventBusSubscriptionHandler(config.EventBusEngine{
		Enabled:   true,
		LogLevel:  conf.SubscriberEventBus.LogLevel,
		Provider:  config.AWSSqs,
		AWSSqsSns: conf.AWSSDKConfig,
		// }, "", lMessaging, connectDisconnectThingMessageHandler, "iotcore-events-conn-disconn", conf.SQSIncomingEventQueueName)
	}, "", lSqsConDiscon, connectDisconnectThingMessageHandler, "iotcore-events-conn-disconn", "aws-iot-events-to-lamassu")
	if err != nil {
		lSqsConDiscon.Errorf("could not generate IoT Connection/Disconnection Event Bus Subscription Handler: %s", err)
	}

	err = connectDisconnectThingSubHandler.RunAsync()
	if err != nil {
		lMessaging.Errorf("could not run IoT Connection/Disconnection Event Bus Subscription Handler: %s", err)
		return nil, err
	}

	lSqsShadowUpd.Infof("starting Shadow Update Event Bus Subscription Handler")
	shadowUpdateMessageHandler := handlers.NewAWSIoTThingShadowUpdateEventHandler(lSqsShadowUpd, awsConnectorSvc)
	shadowUpdateMessageSubHandler, err := eventbus.NewEventBusSubscriptionHandler(config.EventBusEngine{
		Enabled:   true,
		LogLevel:  conf.SubscriberEventBus.LogLevel,
		Provider:  config.AWSSqs,
		AWSSqsSns: conf.AWSSDKConfig,
		// }, "", lMessaging, shadowUpdateMessageHandler, "iotcore-events-conn-disconn", conf.SQSIncomingEventQueueName)
	}, "", lSqsShadowUpd, shadowUpdateMessageHandler, "iotcore-events-shadow-update", "aws-iot-shadow-events-to-lamassu")
	if err != nil {
		lSqsShadowUpd.Errorf("could not generate IoT Shadow Update Event Bus Subscription Handler: %s", err)
	}

	err = shadowUpdateMessageSubHandler.RunAsync()
	if err != nil {
		lSqsShadowUpd.Errorf("could not run IoT Shadow Update Event Bus Subscription Handler: %s", err)
		return nil, err
	}

	return &awsConnectorSvc, nil
}
