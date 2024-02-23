package rabbitmq_test

import (
	"io"
	"strconv"

	"github.com/lamassuiot/lamassuiot/v2/core/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/messaging"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/test/dockerunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/sirupsen/logrus"
)

func RunRabbitMQDocker() (func() error, *config.AMQPConnection, int, error) {
	containerCleanup, container, dockerHost, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "rabbitmq",        // image
		Tag:        "3.12-management", // version
		Env: []string{
			"RABBITMQ_DEFAULT_USER=user",
			"RABBITMQ_DEFAULT_PASS=user",
		},
	}, func(hc *docker.HostConfig) {})
	if err != nil {
		return nil, nil, -1, err
	}

	p, _ := strconv.Atoi(container.GetPort("5672/tcp"))
	adminPort, _ := strconv.Atoi(container.GetPort("15672/tcp"))

	// retry until server is ready
	err = dockerHost.Retry(func() error {
		lgr := logrus.New()
		lgr.SetOutput(io.Discard)
		_, err := messaging.NewMessagingEngine(lgr.WithField("", ""), config.EventBusEngine{
			Enabled:  true,
			LogLevel: config.Info,
			Provider: config.Amqp,
			Amqp: config.AMQPConnection{
				BasicConnection: config.BasicConnection{
					Hostname:  "127.0.0.1",
					Port:      p,
					TLSConfig: config.TLSConfig{},
				},
				BasicAuth: config.AMQPConnectionBasicAuth{Enabled: true, Username: "user", Password: "user"},
				Protocol:  config.AMQP,
				Exchange:  "lamassu",
			},
		}, "")

		return err
	})

	if err != nil {
		containerCleanup()
		return nil, nil, -1, err
	}

	return containerCleanup, &config.AMQPConnection{
		Protocol: config.AMQP,
		BasicConnection: config.BasicConnection{
			Hostname:  "127.0.0.1",
			Port:      p,
			TLSConfig: config.TLSConfig{},
		},
		BasicAuth: config.AMQPConnectionBasicAuth{Enabled: true, Username: "user", Password: "user"},
		Exchange:  "lamassu",
	}, adminPort, nil
}
