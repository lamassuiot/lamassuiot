package inmemory

import (
	"sync"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
)

var (
	// sharedGoChannel is a singleton instance shared by all services in monolithic mode
	// This mimics how all services connect to the same RabbitMQ broker
	sharedGoChannel     *gochannel.GoChannel
	sharedGoChannelOnce sync.Once
	sharedLogger        *logrus.Entry
)

// Register registers the inmemory eventbus engine with the core registry
// This should be called during monolithic initialization
func Register() {
	eventbus.RegisterEventBusEngine("inmemory", func(eventBusProvider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
		return NewInMemoryEngine(serviceId, logger)
	})
}

// InMemoryEngine implements EventBusEngine interface using Watermill's GoChannel
// for ephemeral in-memory pub/sub without external dependencies
type InMemoryEngine struct {
	logger     *logrus.Entry
	serviceID  string
	subscriber message.Subscriber
	publisher  message.Publisher
}

// getSharedGoChannel returns the singleton GoChannel instance
// All services in the monolithic mode share this instance
func getSharedGoChannel(logger *logrus.Entry) *gochannel.GoChannel {
	sharedGoChannelOnce.Do(func() {
		sharedLogger = logger
		lEventBus := eventbus.NewLoggerAdapter(logger.WithField("subsystem-provider", "InMemory - GoChannel"))

		// Create shared GoChannel with configuration suitable for testing
		sharedGoChannel = gochannel.NewGoChannel(
			gochannel.Config{
				// Buffer size for output channels
				OutputChannelBuffer: 64,
				// Persistent: false means messages are not stored after subscriber disconnect
				Persistent: false,
				// BlockPublishUntilSubscriberAck: false for async publishing
				BlockPublishUntilSubscriberAck: false,
			},
			lEventBus,
		)
		logger.Info("Created shared GoChannel instance for inmemory eventbus")
	})
	return sharedGoChannel
}

// NewInMemoryEngine creates a new in-memory eventbus engine using GoChannel
func NewInMemoryEngine(serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	// Get the shared GoChannel instance (singleton)
	_ = getSharedGoChannel(logger)

	return &InMemoryEngine{
		logger:    logger,
		serviceID: serviceId,
	}, nil
}

// Subscriber returns a message.Subscriber implementation
// Lazy-loaded and cached after first call
func (e *InMemoryEngine) Subscriber() (message.Subscriber, error) {
	if e.subscriber == nil {
		// Use the shared GoChannel instance
		pubsub := getSharedGoChannel(e.logger)
		e.subscriber = &goChannelSubscriber{
			pubsub:    pubsub,
			serviceID: e.serviceID,
			logger:    e.logger,
		}
	}
	return e.subscriber, nil
}

// Publisher returns a message.Publisher implementation
// Lazy-loaded and cached after first call
func (e *InMemoryEngine) Publisher() (message.Publisher, error) {
	if e.publisher == nil {
		// Use the shared GoChannel instance
		pubsub := getSharedGoChannel(e.logger)
		e.publisher = &goChannelPublisher{
			pubsub: pubsub,
			logger: e.logger,
		}
	}
	return e.publisher, nil
}
