package eventbus

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/sirupsen/logrus"
)

type EventBusEngine interface {
	Subscriber() (message.Subscriber, error)
	Publisher() (message.Publisher, error)
}

type EventBusBuilder func(eventBusProvider string, config interface{}, serviceId string, logger *logrus.Entry) (EventBusEngine, error)

var engines = map[string]EventBusBuilder{}

func RegisterEventBusEngine(provider string, builder EventBusBuilder) {
	engines[provider] = builder
}

func GetEventBusEngine(provider string, config interface{}, serviceId string, logger *logrus.Entry) (EventBusEngine, error) {
	if builder, ok := engines[provider]; ok {
		return builder(provider, config, serviceId, logger)
	}
	return nil, nil
}
