package eventbus

import (
	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus/builder"
	"github.com/sirupsen/logrus"
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
		logger.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	return engine.Publisher()
}
