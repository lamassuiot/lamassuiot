package amqp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v4/engines/eventbus/amqp/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prepareEventBusForTest(t *testing.T) (func() error, message.Publisher, func(serviceID string) message.Subscriber) {
	cleanup, conf, _, err := rabbitmq_test.RunRabbitMQDocker(false)
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

func TestErrorHandling(t *testing.T) {
	eventbus.TestErrorHandling(t, eventbus.EventBusTestInput{
		SetupEventBus: func() (func() error, message.Publisher, func(serviceID string) message.Subscriber) {
			cleanup, publisher, subFunc := prepareEventBusForTest(t)
			return cleanup, publisher, subFunc
		},
	})
}

// queueInfo is the subset of the RabbitMQ management API queue object these tests assert on.
type queueInfo struct {
	Durable    bool           `json:"durable"`
	AutoDelete bool           `json:"auto_delete"`
	Exclusive  bool           `json:"exclusive"`
	Arguments  map[string]any `json:"arguments"`
}

// getQueue reads a queue from the RabbitMQ management API. It returns the HTTP status code and,
// when the queue exists, its attributes.
func getQueue(t *testing.T, adminPort int, name string) (int, *queueInfo) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/queues/%%2F/%s", adminPort, url.PathEscape(name)), nil)
	if err != nil {
		t.Fatalf("could not build management API request: %s", err)
	}
	req.SetBasicAuth("user", "user")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("management API request failed: %s", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return res.StatusCode, nil
	}

	var q queueInfo
	if err := json.NewDecoder(res.Body).Decode(&q); err != nil {
		t.Fatalf("could not decode queue %q: %s", name, err)
	}
	return res.StatusCode, &q
}

// waitForQueue polls the management API until the queue exists, since the management stats are
// refreshed asynchronously after the queue is declared.
func waitForQueue(t *testing.T, adminPort int, name string) *queueInfo {
	t.Helper()

	var q *queueInfo
	require.Eventually(t, func() bool {
		var status int
		status, q = getQueue(t, adminPort, name)
		return status == http.StatusOK
	}, 30*time.Second, 500*time.Millisecond, "queue %q was not declared", name)
	return q
}

func TestEphemeralSubscriberQueueIsDeletedWithItsConsumer(t *testing.T) {
	cleanup, conf, adminPort, err := rabbitmq_test.RunRabbitMQDocker(false)
	require.NoError(t, err)
	defer cleanup()

	l := helpers.SetupLogger(config.Info, "test", "ephemeral-sub")
	sub, err := NewAMQPEphemeralSub(*conf, "sse-test", l)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = sub.Subscribe(ctx, "device.#")
	require.NoError(t, err)

	const queueName = "device.#_sse-test"
	q := waitForQueue(t, adminPort, queueName)
	assert.True(t, q.Durable, "queue must stay durable so watermill reconnects keep working")
	assert.True(t, q.AutoDelete, "queue must be deleted once its last consumer goes away")
	assert.False(t, q.Exclusive, "queue must not be exclusive so reconnects can re-declare it")
	assert.EqualValues(t, 3600000, q.Arguments["x-expires"], "x-expires must be one hour in ms")

	cancel()
	require.NoError(t, sub.Close())

	require.Eventually(t, func() bool {
		status, _ := getQueue(t, adminPort, queueName)
		return status == http.StatusNotFound
	}, 30*time.Second, 500*time.Millisecond, "queue %q was not deleted after its consumer closed", queueName)
}

func TestDefaultSubscriberQueueIsUnchanged(t *testing.T) {
	cleanup, conf, adminPort, err := rabbitmq_test.RunRabbitMQDocker(false)
	require.NoError(t, err)
	defer cleanup()

	l := helpers.SetupLogger(config.Info, "test", "plain-sub")
	sub, err := NewAMQPSub(*conf, "plain-test", l)
	require.NoError(t, err)
	defer sub.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = sub.Subscribe(ctx, "device.#")
	require.NoError(t, err)

	q := waitForQueue(t, adminPort, "device.#_plain-test")
	assert.True(t, q.Durable)
	assert.False(t, q.AutoDelete)
	assert.NotContains(t, q.Arguments, "x-expires")
}
