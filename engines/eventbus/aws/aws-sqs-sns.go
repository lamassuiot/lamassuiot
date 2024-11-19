package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	wsns "github.com/ThreeDotsLabs/watermill-aws/sns"
	wsqs "github.com/ThreeDotsLabs/watermill-aws/sqs"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	laws "github.com/lamassuiot/lamassuiot/v3/aws"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
)

func NewAwsSqsSub(conf laws.AWSSDKConfig, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	awsConf, err := laws.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	account, err := getAWSAccountID(conf)
	if err != nil {
		logger.Errorf("could not get AWS account ID: %s", err)
		return nil, err
	}

	topicResolver, err := wsns.NewGenerateArnTopicResolver(account, conf.Region)
	if err != nil {
		logger.Errorf("could not create topic resolver: %s", err)
		return nil, err
	}

	lEventBus := eventbus.NewLoggerAdapter(logger.WithField("subsystem-provider", "AWS.SQS - Subscriber"))

	sub, err := wsns.NewSubscriber(
		wsns.SubscriberConfig{
			AWSConfig:     *awsConf,
			TopicResolver: topicResolver,
			GenerateSqsQueueName: func(ctx context.Context, snsTopic wsns.TopicArn) (string, error) {
				topicName, err := wsns.ExtractTopicNameFromTopicArn(snsTopic)
				if err != nil {
					return "", err
				}

				topic := fmt.Sprintf("%v-%v", serviceID, topicName)
				topic = strings.ReplaceAll(topic, ".", "-")
				topic = strings.ReplaceAll(topic, "#", "_")

				return topic, nil
			},
			GenerateSubscribeInput: func(ctx context.Context, params wsns.GenerateSubscribeInputParams) (*sns.SubscribeInput, error) {
				resolvedTopic, err := topicResolver.ResolveTopic(ctx, "lamassu-events-v2")
				if err != nil {
					return nil, err
				}

				subInput := &sns.SubscribeInput{
					Protocol: aws.String("sqs"),
					TopicArn: aws.String(string(resolvedTopic)),
					Endpoint: aws.String(string(params.SqsQueueArn)),
					Attributes: map[string]string{
						"RawMessageDelivery": "true",
					},
				}

				topic := string(params.SnsTopicArn)
				//delete ARN prefix. Just leave the topic name using the last part of the ARN
				topic = strings.Split(topic, ":")[len(strings.Split(topic, ":"))-1]

				if topic != "#" {
					var filterPolicy map[string]any

					if !strings.Contains(topic, "#") {
						filterPolicy = map[string]any{
							"topic": []string{topic},
						}
					} else {
						if strings.HasSuffix(topic, "#") {
							topic, _ = strings.CutSuffix(topic, "#")
							filterPolicy = map[string]any{
								"topic": []any{
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
						return nil, err
					}

					subInput.Attributes["FilterPolicy"] = string(filterPolicyJSON)
					subInput.Attributes["FilterPolicyScope"] = "MessageAttributes"
				}

				return subInput, nil
			},
		},
		wsqs.SubscriberConfig{
			AWSConfig: *awsConf,
		},
		lEventBus,
	)

	if err != nil {
		return nil, err
	}

	return sub, nil
}

func NewAwsSnsPub(conf laws.AWSSDKConfig, logger *logrus.Entry) (message.Publisher, error) {
	awsConf, err := laws.GetAwsSdkConfig(conf)
	if err != nil {
		return nil, err
	}

	account, err := getAWSAccountID(conf)
	if err != nil {
		logger.Errorf("could not get AWS account ID: %s", err)
		return nil, err
	}

	topicResolver, err := wsns.NewGenerateArnTopicResolver(account, conf.Region)
	if err != nil {
		logger.Errorf("could not create topic resolver: %s", err)
		return nil, err
	}

	lEventBus := eventbus.NewLoggerAdapter(logger.WithField("subsystem-provider", "AWS.SNS - Publisher"))

	pub, err := wsns.NewPublisher(
		wsns.PublisherConfig{
			AWSConfig:     *awsConf,
			TopicResolver: topicResolver,
		},
		lEventBus,
	)

	if err != nil {
		return nil, err
	}

	snsPublisher := &snsPublisher{sns: pub}

	return snsPublisher, nil
}

type snsPublisher struct {
	sns *wsns.Publisher
}

func (s *snsPublisher) Publish(topic string, messages ...*message.Message) error {
	newMessages := make([]*message.Message, 0, len(messages))
	for _, msg := range messages {
		msg.Metadata.Set("topic", topic)
		newMessages = append(newMessages, msg)
	}
	return s.sns.Publish("lamassu-events-v2", newMessages...)
}

func (s *snsPublisher) Close() error {
	return s.sns.Close()
}

func getAWSAccountID(awsConfig laws.AWSSDKConfig) (string, error) {
	awsConf, err := laws.GetAwsSdkConfig(awsConfig)
	if err != nil {
		return "", err
	}

	stsClient := sts.NewFromConfig(*awsConf)

	callIDOutput, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}

	return *callIDOutput.Account, nil
}
