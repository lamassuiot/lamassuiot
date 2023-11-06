package rabbitmq_test

import (
	"io"
	"strconv"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/test/dockerunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/sirupsen/logrus"
)

func RunRabbitMQDocker() (func() error, *config.AMQPConnection, error) {
	containerCleanup, container, dockerHost, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "rabbitmq", // image
		Tag:        "3.12",     // version
		Env: []string{
			"RABBITMQ_DEFAULT_USER=user",
			"RABBITMQ_DEFAULT_PASS=user",
		},
	}, func(hc *docker.HostConfig) {})
	if err != nil {
		return nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("5672/tcp"))

	// retry until server is ready
	err = dockerHost.Retry(func() error {
		lgr := logrus.New()
		lgr.SetOutput(io.Discard)
		_, err := messaging.SetupAMQPConnection(lgr.WithField("", ""), config.AMQPConnection{
			LogLevel: config.Info,
			BasicConnection: config.BasicConnection{
				Hostname:  "127.0.0.1",
				Port:      p,
				TLSConfig: config.TLSConfig{},
			},
			BasicAuth: config.AMQPConnectionBasicAuth{Enabled: true, Username: "user", Password: "user"},
			Enabled:   true,
			Protocol:  config.AMQP,
			Exchange:  "lamassu",
		})

		return err
	})

	if err != nil {
		containerCleanup()
		return nil, nil, err
	}

	return containerCleanup, &config.AMQPConnection{
		LogLevel: config.Debug,
		Protocol: config.AMQP,
		BasicConnection: config.BasicConnection{
			Hostname:  "127.0.0.1",
			Port:      p,
			TLSConfig: config.TLSConfig{},
		},
		BasicAuth: config.AMQPConnectionBasicAuth{Enabled: true, Username: "user", Password: "user"},
		Enabled:   true,
		Exchange:  "lamassu",
	}, nil
}
