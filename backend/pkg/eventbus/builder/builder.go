package builder

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp"
	ampq_subsystem "github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp/subsystem"
	"github.com/lamassuiot/lamassuiot/v3/engines/eventbus/aws"
	"github.com/lamassuiot/lamassuiot/v3/engines/eventbus/channel"
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
