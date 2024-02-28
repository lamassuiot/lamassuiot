package eventbus

import (
	"context"
	"fmt"
	"strings"

	"github.com/ThreeDotsLabs/watermill-amazonsqs/sns"
	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsSns "github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"

	"github.com/ThreeDotsLabs/watermill/message"
)

func bindSQSToSNS(snsPub *sns.Publisher, sqsSub *sqs.Subscriber, topic, queueName string) error {
	snsArn, err := snsPub.GetArnTopic(context.Background(), topic)
	if err != nil {
		return err
	}

	err = sqsSub.SubscribeInitialize(queueName)
	if err != nil {
		return err
	}

	queueUrl, err := sqsSub.GetQueueUrl(context.Background(), queueName)
	if err != nil {
		return err
	}

	queueArn, err := sqsSub.GetQueueArn(context.Background(), queueUrl)
	if err != nil {
		return err
	}

	err = snsPub.AddSubscription(context.Background(), &awsSns.SubscribeInput{
		TopicArn: snsArn,
		Protocol: aws.String("sqs"),
		Endpoint: queueArn,
		Attributes: map[string]string{
			"RawMessageDelivery": "true",
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func NewAwsSqsSub(conf config.AWSSDKConfig, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	awsConf, err := config.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	lEventBus := newWithLogger(logger.WithField("subsystem-provider", "AWS.SQS - Subscriber"))

	subscriberSqs, err := sqs.NewSubscriber(sqs.SubscriberConfig{
		AWSConfig: *awsConf,
	}, lEventBus)
	if err != nil {
		return nil, err
	}

	return subscriberSqs, nil
}

type snsToSqsSub struct {
	conf      config.AWSSDKConfig
	serviceID string
	logger    *logrus.Entry
	sub       message.Subscriber
}

func (s *snsToSqsSub) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	pub, err := NewAwsSnsPub(s.conf, s.serviceID, s.logger)
	if err != nil {
		return nil, err
	}

	defer pub.Close()

	snsPub, ok := pub.(*sns.Publisher)
	if !ok {
		return nil, fmt.Errorf("could not cast to SNS Publisher")
	}

	sub, err := NewAwsSqsSub(s.conf, s.serviceID, s.logger)
	if err != nil {
		return nil, err
	}

	sqsSub, ok := sub.(*sqs.Subscriber)
	if !ok {
		return nil, fmt.Errorf("could not cast to SQS Subscriber")
	}

	sanitizedAWSSqsTopicName := strings.ReplaceAll(topic, "#", "wcard")
	sanitizedAWSSqsTopicName = strings.ReplaceAll(sanitizedAWSSqsTopicName, ".", "-")

	//SQS can only have a 80 chars name
	queueName := fmt.Sprintf("%s--%s", sanitizedAWSSqsTopicName, s.serviceID)

	err = bindSQSToSNS(snsPub, sqsSub, topic, queueName)
	if err != nil {
		return nil, err
	}

	s.sub = sub

	fmt.Println("s")

	return sub.Subscribe(ctx, queueName)
}

// Close should flush unsent messages, if publisher is async.

func (s *snsToSqsSub) Close() error {
	return s.sub.Close()
}

func NewAwsSqsBindToSnsSub(conf config.AWSSDKConfig, serviceID string, logger *logrus.Entry) message.Subscriber {
	return &snsToSqsSub{
		conf:      conf,
		serviceID: serviceID,
		logger:    logger,
	}
}

func NewAwsSnsPub(conf config.AWSSDKConfig, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	awsConf, err := config.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	lEventBusPub := newWithLogger(logger.WithField("subsystem-provider", "AWS.SNS - Publisher"))

	pub, err := sns.NewPublisher(sns.PublisherConfig{
		AWSConfig:             *awsConf,
		CreateTopicfNotExists: true,
		CreateTopicConfig: sns.SNSConfigAtrributes{
			DisplayName: serviceID,
		},
	}, lEventBusPub)
	if err != nil {
		return nil, err
	}

	return pub, nil
}
