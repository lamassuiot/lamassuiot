package messaging

import (
	"context"
	"fmt"
	"strings"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-amazonsqs/sns"
	"github.com/ThreeDotsLabs/watermill-amazonsqs/sqs"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsSns "github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/ThreeDotsLabs/watermill/message"
)

type watermillAWSPublisherAdapter struct {
	publisher *sns.Publisher
	topic     string
}

func (pub *watermillAWSPublisherAdapter) Publish(topic string, messages ...*message.Message) error {
	adaptedMessages := []*message.Message{}
	for _, message := range messages {
		message.Metadata.Set("routing_key", topic)
		adaptedMessages = append(adaptedMessages, message)
	}

	return pub.publisher.Publish(pub.topic, adaptedMessages...)
}

func (pub *watermillAWSPublisherAdapter) Close() error {
	return pub.publisher.Close()
}

type watermillAWSSubscriberAdapter struct {
	publisher     *sns.Publisher
	logger        watermill.LoggerAdapter
	awsConf       *aws.Config
	serviceID     string
	subscriberSqs *sqs.Subscriber
}

func (sub *watermillAWSSubscriberAdapter) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	snsArn, err := sub.publisher.GetArnTopic(ctx, engineHandler)
	if err != nil {
		return nil, err
	}

	subscriberSqs, err := sqs.NewSubscriber(sqs.SubscriberConfig{
		AWSConfig: *sub.awsConf,
	}, sub.logger)
	if err != nil {
		return nil, err
	}

	sanitizedAWSSqsTopicName := strings.ReplaceAll(topic, "#", "wcard")
	sanitizedAWSSqsTopicName = strings.ReplaceAll(sanitizedAWSSqsTopicName, ".", "-")

	//SQS can only have a 80 chars name
	queueName := fmt.Sprintf("%s--%s", sanitizedAWSSqsTopicName, sub.serviceID)
	err = subscriberSqs.SubscribeInitialize(queueName)
	if err != nil {
		return nil, err
	}

	queueUrl, err := subscriberSqs.GetQueueUrl(ctx, queueName)
	if err != nil {
		return nil, err
	}

	queueArn, err := subscriberSqs.GetQueueArn(ctx, queueUrl)
	if err != nil {
		return nil, err
	}

	err = sub.publisher.AddSubscription(ctx, &awsSns.SubscribeInput{
		TopicArn: snsArn,
		Protocol: aws.String("sqs"),
		Endpoint: queueArn,
		Attributes: map[string]string{
			"RawMessageDelivery": "true",
		},
	})

	if err != nil {
		return nil, err
	}

	sub.subscriberSqs = subscriberSqs
	return subscriberSqs.Subscribe(ctx, topic)
}

func (sub *watermillAWSSubscriberAdapter) Close() error {
	return sub.subscriberSqs.Close()
}
