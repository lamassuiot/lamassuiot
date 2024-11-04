package eventbus

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus/builder"
	"github.com/sirupsen/logrus"
)

func NewEventBusSubscriber(conf config.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {

	conf2, err := config.MigrateEventBusToV2Config(conf)
	if err != nil {
		return nil, fmt.Errorf("could not migrate event bus config: %s", err)
	}

	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf2.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	return engine.Subscriber()

}

func NewEventBusPublisher(conf config.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	conf2, err := config.MigrateEventBusToV2Config(conf)
	if err != nil {
		return nil, fmt.Errorf("could not migrate event bus config: %s", err)
	}

	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf2.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	return engine.Publisher()
}
