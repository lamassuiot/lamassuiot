package aws

import (
	"strconv"

	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	aconfig "github.com/lamassuiot/lamassuiot/v2/crypto/aws/config"
	"github.com/sirupsen/logrus"
)

func NewAwsSqsSub(conf aconfig.AWSSDKConfig, serviceID string, logger *logrus.Entry) (*sqs.Subscriber, error) {
	awsConf, err := aconfig.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	lEventBus := newWithLogger(logger.WithField("subsystem-provider", "AWS.SQS - Subscriber"))

	subscriberSqs, err := sqs.NewSubscriber(sqs.SubscriberConfig{
		AWSConfig: *awsConf,
		CreateQueueInitializerConfig: sqs.QueueConfigAtrributes{
			ReceiveMessageWaitTimeSeconds: strconv.Itoa(10),
		},
	}, lEventBus)
	if err != nil {
		return nil, err
	}

	return subscriberSqs, nil
}
