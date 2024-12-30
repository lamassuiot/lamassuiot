package rabbitmq_test

import (
	"fmt"
	"io"
	"net/url"
	"strconv"

	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	ampq "github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/sirupsen/logrus"
)

func RunRabbitMQDocker() (func() error, *ampq.AMQPConnection, int, error) {
	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker(dockertest.RunOptions{
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

		userPassUrlPrefix := fmt.Sprintf("%s:%s@", url.PathEscape("user"), url.PathEscape("user"))
		amqpURI := fmt.Sprintf("%s://%s%s:%d", "amqp", userPassUrlPrefix, "127.0.0.1", p)
		amqpConfig := amqp.NewDurablePubSubConfig(amqpURI, amqp.GenerateQueueNameTopicNameWithSuffix("test-docker"))

		_, err := amqp.NewPublisher(amqpConfig, nil)

		return err
	})

	if err != nil {
		containerCleanup()
		return nil, nil, -1, err
	}

	return containerCleanup, &ampq.AMQPConnection{
		Protocol: ampq.AMQP,
		BasicConnection: cconfig.BasicConnection{
			Hostname:  "127.0.0.1",
			Port:      p,
			TLSConfig: cconfig.TLSConfig{},
		},
		BasicAuth: ampq.AMQPConnectionBasicAuth{Enabled: true, Username: "user", Password: "user"},
		Exchange:  "lamassu",
	}, adminPort, nil
}
