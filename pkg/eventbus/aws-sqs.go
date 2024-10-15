package eventbus

import (
	"strconv"

	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewAwsSqsSub(conf config.AWSSDKConfig, serviceID string, logger *logrus.Entry) (*sqs.Subscriber, error) {
	awsConf, err := config.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	lEventBus := newWithLogger(logger.WithField("subsystem-provider", "AWS.SQS - Subscriber"))

	subscriberSqs, err := sqs.NewSubscriber(sqs.SubscriberConfig{
		AWSConfig: *awsConf,
		CreateQueueInitializerConfig: sqs.QueueConfigAtrributes{
			ReceiveMessageWaitTimeSeconds: strconv.Itoa(0),
		},
	}, lEventBus)
	if err != nil {
		return nil, err
	}

	return subscriberSqs, nil
}

func NewAwsSqsPub(conf config.AWSSDKConfig, serviceID string, logger *logrus.Entry) (*sqs.Publisher, error) {
	awsConf, err := config.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	lEventBus := newWithLogger(logger.WithField("subsystem-provider", "AWS.SQS - Publisher"))

	subscriberSqs, err := sqs.NewPublisher(sqs.PublisherConfig{
		AWSConfig: *awsConf,
		CreateQueueConfig: sqs.QueueConfigAtrributes{
			ReceiveMessageWaitTimeSeconds: strconv.Itoa(0),
		},
		CreateQueueIfNotExists: true,
		Marshaler:              sqs.DefaultMarshalerUnmarshaler{},
	}, lEventBus)
	if err != nil {
		return nil, err
	}

	return subscriberSqs, nil
}
