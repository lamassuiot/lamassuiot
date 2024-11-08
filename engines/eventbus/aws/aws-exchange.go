package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ThreeDotsLabs/watermill-amazonsqs/sns"
	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsSns "github.com/aws/aws-sdk-go-v2/service/sns"
	awsSqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/sirupsen/logrus"

	"github.com/ThreeDotsLabs/watermill/message"
)

type SnsExchangeBuilder struct {
	Config       cconfig.AWSSDKConfig
	ExchangeName string
	ServiceID    string
	Logger       *logrus.Entry
}

func bindSQSToSNS(builder SnsExchangeBuilder, sqsSub *sqs.Subscriber, snsPub *sns.Publisher, topic string) error {
	snsArn, err := snsPub.GetArnTopic(context.Background(), "lamassu-events")
	if err != nil {
		return err
	}

	queueName := builder.ServiceID

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

	awsConf, err := cconfig.GetAwsSdkConfig(builder.Config)
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
			return err
		}

		subAttributes["FilterPolicy"] = string(filterPolicyJSON)
		subAttributes["FilterPolicyScope"] = "MessageAttributes"

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

type exchangeSqsSubscriber struct {
	builderConf SnsExchangeBuilder
	sqsSub      *sqs.Subscriber
}

func (s *exchangeSqsSubscriber) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	pub, err := NewSnsExchangePublisher(s.builderConf)
	if err != nil {
		return nil, err
	}

	defer pub.Close()

	sqsSub, err := NewAwsSqsSub(s.builderConf.Config, s.builderConf.ServiceID, s.builderConf.Logger)
	if err != nil {
		return nil, err
	}

	err = bindSQSToSNS(s.builderConf, sqsSub, pub.getRawSNSPublisher(), topic)
	if err != nil {
		return nil, err
	}

	s.sqsSub = sqsSub

	queueName := s.builderConf.ServiceID
	return sqsSub.Subscribe(ctx, queueName)
}

type SnsExchangeSubscriber struct {
}

// Close should flush unsent messages, if publisher is async.

func (s *exchangeSqsSubscriber) Close() error {
	return s.sqsSub.Close()
}

func NewSnsExchangeSubscriber(builder SnsExchangeBuilder) message.Subscriber {
	return &exchangeSqsSubscriber{
		builderConf: builder,
	}
}

type SnsExchangePublisher struct {
	builderConf SnsExchangeBuilder
	sns         *sns.Publisher
}

func (s *SnsExchangePublisher) Publish(topic string, messages ...*message.Message) error {
	newMessages := make([]*message.Message, 0, len(messages))
	for _, msg := range messages {
		msg.Metadata.Set("topic", topic)
		newMessages = append(newMessages, msg)
	}
	return s.sns.Publish(s.builderConf.ExchangeName, newMessages...)
}

func (s *SnsExchangePublisher) Close() error {
	return s.sns.Close()
}

func (s *SnsExchangePublisher) getRawSNSPublisher() *sns.Publisher {
	return s.sns
}

func NewSnsExchangePublisher(builder SnsExchangeBuilder) (*SnsExchangePublisher, error) {
	awsConf, err := cconfig.GetAwsSdkConfig(builder.Config)
	if err != nil {
		return nil, err
	}

	lEventBusPub := newWithLogger(builder.Logger.WithField("subsystem-provider", "AWS.SNS - Publisher"))
	httpCli, _ := chelpers.BuildHTTPClientWithTracerLogger(&http.Client{}, builder.Logger)
	awsConf.HTTPClient = httpCli

	pub, err := sns.NewPublisher(sns.PublisherConfig{
		AWSConfig:             *awsConf,
		CreateTopicfNotExists: true,
		CreateTopicConfig: sns.SNSConfigAtrributes{
			DisplayName: builder.ExchangeName,
		},
	}, lEventBusPub)
	if err != nil {
		return nil, err
	}

	return &SnsExchangePublisher{
		sns:         pub,
		builderConf: builder,
	}, nil
}
