package builder

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3"
	ampq_subsystem "github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3/subsystem"
	"github.com/lamassuiot/lamassuiot/engines/eventbus/aws/v3"
	"github.com/lamassuiot/lamassuiot/engines/eventbus/channel/v3"
	"github.com/sirupsen/logrus"
)

func BuildEventBusEngine(provider string, config interface{}, serviceId string, logger *logrus.Entry) (eventbus.EventBusEngine, error) {
	return eventbus.GetEventBusEngine(provider, config, serviceId, logger)
}

func init() {
	amqp.Register()
	ampq_subsystem.Register()
	aws.Register()
	channel.Register()
}
