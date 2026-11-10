package eventbus

import (
	"github.com/ThreeDotsLabs/watermill/message"
	// Import the builder for its provider registration side effects.
	_ "github.com/lamassuiot/lamassuiot/v4/backend/pkg/eventbus/builder"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	coreeventbus "github.com/lamassuiot/lamassuiot/v4/core/pkg/eventbus"
	"github.com/sirupsen/logrus"
)

func NewEventBusSubscriber(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	return coreeventbus.NewEventBusSubscriber(conf, serviceID, logger)
}

func NewEventBusPublisher(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	return coreeventbus.NewEventBusPublisher(conf, serviceID, logger)
}
