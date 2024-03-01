package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThreeDotsLabs/watermill-amazonsqs/sns"
	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsSns "github.com/aws/aws-sdk-go-v2/service/sns"
	awsSqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"

	"github.com/ThreeDotsLabs/watermill/message"
)

func bindSQSToSNS(conf config.AWSSDKConfig, snsPub *sns.Publisher, sqsSub *sqs.Subscriber, topic, queueName string) error {
	snsArn, err := snsPub.GetArnTopic(context.Background(), "lamassu-events")
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

	awsConf, err := config.GetAwsSdkConfig(conf)
	if err != nil {
		return err
	}

	sqsCli := awsSqs.NewFromConfig(*awsConf)
	policyBuilder := func(sqsQueueArn, snsTopicArn string) (string, error) {
		pMap := map[string]any{
			"Version": "2012-10-17",
			"Statement": []map[string]any{
				{
					"Effect": "Allow",
					"Principal": map[string]any{
						"Service": "sns.amazonaws.com",
					},
					"Action":   "sqs:sendmessage",
					"Resource": sqsQueueArn,
					"Condition": map[string]any{
						"ArnEquals": map[string]any{
							"aws:SourceArn": snsTopicArn,
						},
					},
				},
			},
		}

		pBytes, err := json.Marshal(pMap)
		if err != nil {
			return "", err
		}

		return string(pBytes), nil
	}

	policy, err := policyBuilder(*queueArn, *snsArn)
	if err != nil {
		return err
	}

	subAttributes := map[string]string{
		"RawMessageDelivery": "true",
	}

	if topic != "#" {
		var filterPolicy map[string]any

		if !strings.Contains(topic, "#") {
			filterPolicy = map[string]any{
				"type": []string{topic},
			}
		} else {
			if strings.HasSuffix(topic, "#") {
				topic, _ = strings.CutSuffix(topic, "#")
				filterPolicy = map[string]any{
					"type": []any{
						map[string]any{
							"prefix": topic,
						},
					},
				}
			}
		}

		filterPolicyJSON, err := json.Marshal(filterPolicy)
		if err != nil {
			fmt.Println("error marshalling filter policy:", err)
			return err
		}

		subAttributes["FilterPolicy"] = string(filterPolicyJSON)
		subAttributes["FilterPolicyScope"] = "MessageBody"

	}

	_, err = sqsCli.SetQueueAttributes(context.Background(), &awsSqs.SetQueueAttributesInput{
		QueueUrl: queueUrl,
		Attributes: map[string]string{
			"Policy": policy,
		},
	})
	if err != nil {
		return err
	}

	err = snsPub.AddSubscription(context.Background(), &awsSns.SubscribeInput{
		TopicArn:   snsArn,
		Protocol:   aws.String("sqs"),
		Endpoint:   queueArn,
		Attributes: subAttributes,
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
		CreateQueueInitializerConfig: sqs.QueueConfigAtrributes{
			ReceiveMessageWaitTimeSeconds: strconv.Itoa(10),
		},
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

	snsPub, ok := pub.(*snsPublisher)
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
	fmt.Println(queueName, topic)

	err = bindSQSToSNS(s.conf, snsPub.pub, sqsSub, topic, queueName)
	if err != nil {
		return nil, err
	}

	s.sub = sub

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

type snsPublisher struct {
	pub *sns.Publisher
}

func (s *snsPublisher) Publish(topic string, messages ...*message.Message) error {
	return s.pub.Publish("lamassu-events", messages...)
}

func (s *snsPublisher) Close() error {
	return s.pub.Close()
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
			DisplayName: "lamassu-events",
		},
	}, lEventBusPub)
	if err != nil {
		return nil, err
	}

	return &snsPublisher{
		pub: pub,
	}, nil
}
