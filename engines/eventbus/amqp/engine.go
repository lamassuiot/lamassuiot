package amqp

import (
	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/eventbus/amqp/config"
	"github.com/sirupsen/logrus"
)

func Register() {
	eventbus.RegisterEventBusEngine("amqp", func(eventBusProvider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
		return NewAmqpEngine(config, serviceId, logger)
	})
}

type AmqpEngine struct {
	logger     *logrus.Entry
	config     config.AMQPConnection
	serviceID  string
	subscriber message.Subscriber
	publisher  message.Publisher
}

func NewAmqpEngine(conf interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	localConf, err := cconfig.DecodeStruct[config.AMQPConnection](conf)
	if err != nil {
		logger.Errorf("could not decode AMQP Connection config: %s", err)
		return nil, err
	}
	return &AmqpEngine{
		logger:    logger,
		config:    localConf,
		serviceID: serviceId,
	}, nil
}

func (e *AmqpEngine) Subscriber() (message.Subscriber, error) {
	if e.subscriber == nil {

		subscriber, err := NewAMQPSub(e.config, e.serviceID, e.logger)

		if err != nil {
			e.logger.Errorf("could not generate Event Bus Subscriber: %s", err)
			return nil, err
		}
		e.subscriber = subscriber
	}
	return e.subscriber, nil
}

func (e *AmqpEngine) Publisher() (message.Publisher, error) {
	if e.publisher == nil {
		publisher, err := NewAMQPPub(e.config, e.serviceID, e.logger)
		if err != nil {
			e.logger.Errorf("could not generate Event Bus Publisher: %s", err)
			return nil, err
		}
		e.publisher = publisher
	}

	return e.publisher, nil
}
