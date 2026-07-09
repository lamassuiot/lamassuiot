package rabbitmq_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/ThreeDotsLabs/watermill-amqp/v2/pkg/amqp"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	ampq "github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/moby/moby/api/types/network"
	"github.com/ory/dockertest/v4"
	"github.com/sirupsen/logrus"
)

func RunRabbitMQDocker(exposeAsStandardPort bool) (func() error, *ampq.AMQPConnection, int, error) {
	runOpts := []dockertest.RunOption{
		dockertest.WithTag("3.12-management"),
		dockertest.WithEnv([]string{
			"RABBITMQ_DEFAULT_USER=user",
			"RABBITMQ_DEFAULT_PASS=user",
		}),
		dockertest.WithLabels(map[string]string{
			"group": "lamassuiot-monolithic",
		}),
	}
	if exposeAsStandardPort {
		runOpts = append(runOpts, dockertest.WithPortBindings(network.PortMap{
			network.MustParsePort("5672/tcp"): []network.PortBinding{
				{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "5672"},
			},
			network.MustParsePort("15672/tcp"): []network.PortBinding{
				{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "15672"},
			},
		}))
	}

	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker("rabbitmq", runOpts...)
	if err != nil {
		return nil, nil, -1, err
	}

	p, _ := strconv.Atoi(container.GetPort("5672/tcp"))
	adminPort, _ := strconv.Atoi(container.GetPort("15672/tcp"))

	// retry until server is ready
	err = dockerHost.Retry(context.Background(), 30*time.Second, func() error {
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
