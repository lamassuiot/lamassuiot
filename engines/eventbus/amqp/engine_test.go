package amqp

import (
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp/test"
)

func prepareEventBusForTest(t *testing.T) (func() error, message.Publisher, func(serviceID string) message.Subscriber) {
	cleanup, conf, _, err := rabbitmq_test.RunRabbitMQDocker()
	if err != nil {
		t.Fatalf("could not run RabbitMQ docker: %s", err)
	}

	lPub := helpers.SetupLogger(config.Info, "test", "test-pub")
	publisher, err := NewAMQPPub(*conf, "test", lPub)
	if err != nil {
		cleanup()
		t.Fatalf("could not create publisher: %s", err)
	}

	subFunc := func(serviceID string) message.Subscriber {
		lSub := helpers.SetupLogger(config.Info, "service", serviceID)
		subscriber, err := NewAMQPSub(*conf, serviceID, lSub)
		if err != nil {
			cleanup()
			t.Fatalf("could not create subscriber: %s", err)
		}

		return subscriber
	}

	return cleanup, publisher, subFunc
}

func TestMultiServiceSubscribe(t *testing.T) {
	eventbus.TestMultiServiceSubscribe(t, eventbus.EventBusTestInput{
		SetupEventBus: func() (func() error, message.Publisher, func(serviceID string) message.Subscriber) {
			cleanup, publisher, subFunc := prepareEventBusForTest(t)
			return cleanup, publisher, subFunc
		},
	})
}

func TestMultiConsumers(t *testing.T) {
	eventbus.TestMultiConsumers(t, eventbus.EventBusTestInput{
		SetupEventBus: func() (func() error, message.Publisher, func(serviceID string) message.Subscriber) {
			cleanup, publisher, subFunc := prepareEventBusForTest(t)
			return cleanup, publisher, subFunc
		},
	})
}

func TestWildcardSubscribe(t *testing.T) {
	eventbus.TestWildcardSubscribe(t, eventbus.EventBusTestInput{
		SetupEventBus: func() (func() error, message.Publisher, func(serviceID string) message.Subscriber) {
			cleanup, publisher, subFunc := prepareEventBusForTest(t)
			return cleanup, publisher, subFunc
		},
	})
}
