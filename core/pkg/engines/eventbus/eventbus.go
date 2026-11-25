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

// EphemeralSubscriberEngine is implemented by engines that can build a subscriber whose broker-side
// state (such as an AMQP queue) is removed once the subscriber goes away, instead of lingering until
// cleaned up out-of-band. It is meant for per-process subscribers such as the SSE fan-out one.
// Unlike EventBusEngine.Subscriber, every call returns a new subscriber.
type EphemeralSubscriberEngine interface {
	EphemeralSubscriber() (message.Subscriber, error)
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
