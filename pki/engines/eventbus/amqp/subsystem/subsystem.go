package subsystem

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/pki/v3/engines/eventbus/amqp/test"
	"github.com/lamassuiot/lamassuiot/pki/v3/shared/subsystems/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.RabbitMQ, &RabbitMQSubsystem{})
}

type RabbitMQSubsystem struct {
}

func (p *RabbitMQSubsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	cleanup, conf, adminPort, err := rabbitmq_test.RunRabbitMQDocker(exposeAsStandardPort)
	if err != nil {
		return nil, err
	}

	eventBusConfig, err := config.EncodeStruct(conf)
	if err != nil {
		return nil, err
	}

	return &subsystems.SubsystemBackend{
		Config: config.EventBusEngine{
			LogLevel: config.Trace,
			Enabled:  true,
			Provider: config.Amqp,
			Config:   eventBusConfig,
		},
		Extra: &map[string]interface{}{
			"adminPort": adminPort,
		},
		AfterSuite: func() { cleanup() },
		BeforeEach: func() error {
			return nil
		},
	}, nil

}
