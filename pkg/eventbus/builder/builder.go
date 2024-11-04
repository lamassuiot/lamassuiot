package builder

import (
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/eventbus/amqp"
	"github.com/lamassuiot/lamassuiot/v2/eventbus/aws"
	"github.com/lamassuiot/lamassuiot/v2/eventbus/channel"
	"github.com/sirupsen/logrus"
)

func BuildEventBusEngine(provider string, config map[string]interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	return eventbus.GetEventBusEngine(provider, config, serviceId, logger)
}

func init() {
	amqp.Register()
	aws.Register()
	channel.Register()
}
