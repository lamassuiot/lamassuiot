package assemblers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
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

	awsCfg, err := config.GetAwsSdkConfig(conf.AWSSDKConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get aws config: %s", err)
	}

	awsConnectorSvc, err := iot.NewAWSCloudConnectorServiceService(iot.AWSCloudConnectorBuilder{
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
