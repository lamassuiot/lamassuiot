package eventbus

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	wotel "github.com/voi-oss/watermill-opentelemetry/pkg/opentelemetry"
)

func NewEventBusSubscriber(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	return engine.Subscriber()
}

func NewEventBusPublisher(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Publisher: %s", err)
		return nil, err
	}

	pub, err := engine.Publisher()
	if err != nil {
		logger.Errorf("could not generate Event Bus Publisher: %s", err)
		return nil, err
	}

	return wotel.NewPublisherDecorator(pub), nil
}
