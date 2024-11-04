package aws

import (
	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/eventbus"
	aconfig "github.com/lamassuiot/lamassuiot/v2/crypto/aws/config"
	"github.com/sirupsen/logrus"
)

func Register() {
	eventbus.RegisterEventBusEngine("aws_sqs_sns", func(eventBusProvider string, config map[string]interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
		return NewAWSEngine(config, serviceId, logger)
	})
}

type AwsEngine struct {
	logger     *logrus.Entry
	config     aconfig.AWSSDKConfig
	serviceID  string
	subscriber message.Subscriber
	publisher  message.Publisher
}

func NewAWSEngine(conf map[string]interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	localConf, err := cconfig.DecodeStruct[aconfig.AWSSDKConfig](conf)
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

		subscriber := NewSnsExchangeSubscriber(SnsExchangeBuilder{
			Config:       e.config,
			ExchangeName: "lamassu-events",
			ServiceID:    e.serviceID,
			Logger:       e.logger,
		})

		e.subscriber = subscriber
	}
	return e.subscriber, nil
}

func (e *AwsEngine) Publisher() (message.Publisher, error) {
	if e.publisher == nil {
		publisher, err := NewSnsExchangePublisher(SnsExchangeBuilder{
			Config:       e.config,
			ExchangeName: "lamassu-events",
			ServiceID:    e.serviceID,
			Logger:       e.logger,
		})
		if err != nil {
			e.logger.Errorf("could not generate Event Bus Publisher: %s", err)
			return nil, err
		}
		e.publisher = publisher
	}

	return e.publisher, nil
}
