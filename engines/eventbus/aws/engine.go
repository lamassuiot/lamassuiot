package aws

import (
	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
	"github.com/sirupsen/logrus"
)

func Register() {
	eventbus.RegisterEventBusEngine("aws_sqs_sns", func(eventBusProvider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
		return NewAWSEngine(config, serviceId, logger)
	})
}

type AwsEngine struct {
	logger     *logrus.Entry
	config     laws.AWSSDKConfig
	serviceID  string
	subscriber message.Subscriber
	publisher  message.Publisher
}

func NewAWSEngine(conf interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	localConf, err := cconfig.DecodeStruct[laws.AWSSDKConfig](conf)
	if err != nil {
		logger.Errorf("could not decode AMQP Connection config: %s", err)
		return nil, err
	}
	return &AwsEngine{
		logger:    logger,
		config:    localConf,
		serviceID: serviceId,
	}, nil
}

func (e *AwsEngine) Subscriber() (message.Subscriber, error) {
	if e.subscriber == nil {
		subscriber, err := NewAwsSqsSub(
			e.config,
			e.serviceID,
			e.logger,
		)
		if err != nil {
			e.logger.Errorf("could not generate Event Bus Subscriber: %s", err)
			return nil, err
		}

		e.subscriber = subscriber
	}
	return e.subscriber, nil
}

func (e *AwsEngine) Publisher() (message.Publisher, error) {
	if e.publisher == nil {
		publisher, err := NewAwsSnsPub(
			e.config,
			e.logger,
		)
		if err != nil {
			e.logger.Errorf("could not generate Event Bus Publisher: %s", err)
			return nil, err
		}

		e.publisher = publisher
	}

	return e.publisher, nil
}
