package aws

import (
	"strconv"

	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewAwsSqsSub(conf cconfig.AWSSDKConfig, serviceID string, logger *logrus.Entry) (*sqs.Subscriber, error) {
	awsConf, err := cconfig.GetAwsSdkConfig(conf)
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
