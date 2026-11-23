package eventbus

import (
	"sync"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/sirupsen/logrus"
)

type EventBusEngine interface {
	Subscriber() (message.Subscriber, error)
	Publisher() (message.Publisher, error)
}

type EventBusBuilder func(eventBusProvider string, config any, serviceId string, logger *logrus.Entry) (EventBusEngine, error)

var (
	enginesMu sync.RWMutex
	engines   = map[string]EventBusBuilder{}
)

func RegisterEventBusEngine(provider string, builder EventBusBuilder) {
	enginesMu.Lock()
	defer enginesMu.Unlock()

	engines[provider] = builder
}

func GetEventBusEngine(provider string, config any, serviceId string, logger *logrus.Entry) (EventBusEngine, error) {
	enginesMu.RLock()
	builder, ok := engines[provider]
	enginesMu.RUnlock()

	if ok {
		return builder(provider, config, serviceId, logger)
	}
	return nil, nil
}
