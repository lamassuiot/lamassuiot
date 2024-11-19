package aws

import (
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v3/aws"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
)

func prepareEventBusForTest(t *testing.T) (message.Publisher, func(serviceID string) message.Subscriber) {
	cleanup, conf, err := aws.RunAWSEmulationLocalStackDocker()
	if err != nil {
		t.Fatalf("could not run RabbitMQ docker: %s", err)
	}

	lPub := helpers.SetupLogger(config.Info, "test", "test-pub")
	publisher, err := NewAwsSnsPub(*conf, lPub)
	if err != nil {
		cleanup()
		t.Fatalf("could not create publisher: %s", err)
	}

	subFunc := func(serviceID string) message.Subscriber {
		lSub := helpers.SetupLogger(config.Info, "service", serviceID)
		subscriber, err := NewAwsSqsSub(*conf, serviceID, lSub)
		if err != nil {
			cleanup()
			t.Fatalf("could not create subscriber: %s", err)
		}

		return subscriber
	}

	return publisher, subFunc
}

func TestMultiServiceSubscribe(t *testing.T) {
	publisher, subFunc := prepareEventBusForTest(t)
	eventbus.TestMultiServiceSubscribe(t, publisher, subFunc)
}
func TestMultiConsumers(t *testing.T) {
	publisher, subFunc := prepareEventBusForTest(t)
	eventbus.TestMultiConsumers(t, publisher, subFunc)
}
func TestWildcardSubscribe(t *testing.T) {
	publisher, subFunc := prepareEventBusForTest(t)
	eventbus.TestWildcardSubscribe(t, publisher, subFunc)
}
