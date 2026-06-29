package builder

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
)

func BuildEventBusEngine(provider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	return eventbus.GetEventBusEngine(provider, config, serviceId, logger)
}
