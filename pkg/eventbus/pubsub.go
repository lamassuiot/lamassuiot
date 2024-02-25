package eventbus

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewEventBusSubscriber(conf config.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	switch conf.Provider {
	case config.Amqp:
		return NewAMQPSub(conf.Amqp, serviceID, logger)
	}

	return nil, fmt.Errorf("unsupported subscriber provider: %s", conf.Provider)
}

func NewEventBusPublisher(conf config.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	switch conf.Provider {
	case config.Amqp:
		return NewAMQPPub(conf.Amqp, serviceID, logger)
	}

	return nil, fmt.Errorf("unsupported subscriber provider: %s", conf.Provider)
}
