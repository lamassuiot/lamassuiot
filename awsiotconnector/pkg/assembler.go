package pkg

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/eventbus"
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	ceventbus "github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/services"
	"github.com/sirupsen/logrus"
)

func AssembleAWSIoTManagerService(conf ConnectorServiceConfig, caService services.CAService, dmsService services.DMSManagerService, deviceService services.DeviceManagerService) (*AWSCloudConnectorService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "AWS IoT Connector", "Service")
	lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "AWS IoT Connector", "Event Bus")

	awsCfg, err := cconfig.GetAwsSdkConfig(conf.AWSSDKConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get aws config: %s", err)
	}

	awsConnectorSvc, err := NewAWSCloudConnectorServiceService(AWSCloudConnectorBuilder{
		Conf:        *awsCfg,
		Logger:      lSvc,
		ConnectorID: conf.ConnectorID,
		CaSDK:       caService,
		DmsSDK:      dmsService,
		DeviceSDK:   deviceService,
	})
	if err != nil {
		logrus.Fatal(err)
	}

	serviceID := fmt.Sprintf("aws-connector-%s", strings.ReplaceAll(conf.ConnectorID, "aws.", "-"))
	eventHandlers := NewAWSIoTEventHandler(lMessaging, awsConnectorSvc)
	subscriber, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, serviceID, lMessaging)
	if err != nil {
		lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	routerHandler, err := ceventbus.NewEventBusMessageHandler("AWSConnector-DEFAULT", "#", subscriber, lMessaging, *eventHandlers)
	if err != nil {
		lMessaging.Errorf("could not generate Event Bus Subscription Handler: %s", err)
	}

	err = routerHandler.RunAsync()
	if err != nil {
		lMessaging.Errorf("could not run Event Bus Subscription Handler: %s", err)
		return nil, err
	}

	go func() {
		lSvc.Infof("starting SQS thread")
		sqsQueueName := fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", awsConnectorSvc.GetRegion(), awsConnectorSvc.GetAccountID(), conf.AWSBidirectionalQueueName)

		for {
			lSvc.Debugf("reading from queue %s", sqsQueueName)
			sqsService := awsConnectorSvc.GetSQSService()
			sqsOutput, err := sqsService.ReceiveMessage(context.Background(), &sqs.ReceiveMessageInput{
				QueueUrl:            aws.String(sqsQueueName),
				MaxNumberOfMessages: int32(10),
				WaitTimeSeconds:     int32(20),
			})

			if err != nil {
				lSvc.Errorf("could not receive SQS messages: %s", err)
				return
			}

			totalInBatch := len(sqsOutput.Messages)
			lSvc.Tracef("received sqs batch messages of size %d ", totalInBatch)
			for idx, sqsMessage := range sqsOutput.Messages {
				lSvc.Tracef("message [%d/%d]: %s", idx+1, totalInBatch, *sqsMessage.Body)
			}
		}
	}()

	return &awsConnectorSvc, nil
}
