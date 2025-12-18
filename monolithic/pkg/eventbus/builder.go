package eventbus

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/eventbus/inmemory"
	"github.com/sirupsen/logrus"
)

// BuildEventBusEngine builds an eventbus engine with monolithic-specific support
// This extends the core eventbus registry with the inmemory GoChannel implementation
func BuildEventBusEngine(provider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	// Handle inmemory provider specifically for monolithic mode
	if provider == "inmemory" {
		return inmemory.NewInMemoryEngine(serviceId, logger)
	}

	// Fall back to core eventbus registry for AMQP, AWS, etc.
	return eventbus.GetEventBusEngine(provider, config, serviceId, logger)
}
