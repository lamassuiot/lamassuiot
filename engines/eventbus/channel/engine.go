package channel

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
)

func Register() {
	eventbus.RegisterEventBusEngine("channel", func(eventBusProvider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
		return NewChannelEngine(config, serviceId, logger)
	})
}

type ChannelEngine struct {
	logger     *logrus.Entry
	serviceID  string
	subscriber message.Subscriber
	publisher  message.Publisher
}

func NewChannelEngine(conf interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	pub, sub := NewGoChannelPubSub(logger)

	return &ChannelEngine{
		logger:     logger,
		serviceID:  serviceId,
		publisher:  pub,
		subscriber: sub,
	}, nil
}

func (e *ChannelEngine) Subscriber() (message.Subscriber, error) {
	return e.subscriber, nil
}

func (e *ChannelEngine) Publisher() (message.Publisher, error) {
	return e.publisher, nil
}
