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

// mgmtClient is used for every RabbitMQ management API call so a hung broker cannot block a test.
var mgmtClient = &http.Client{Timeout: 10 * time.Second}

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

// queueConsumerConnections returns the names of the AMQP connections that currently consume from
// the queue, according to the RabbitMQ management API. ok is false if the API call failed.
func queueConsumerConnections(adminPort int, queue string) (conns []string, ok bool) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/consumers/%%2F", adminPort), nil)
	if err != nil {
		return nil, false
	}
	req.SetBasicAuth("user", "user")

	res, err := mgmtClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, false
	}

	var consumers []struct {
		Queue struct {
			Name string `json:"name"`
		} `json:"queue"`
		ChannelDetails struct {
			ConnectionName string `json:"connection_name"`
		} `json:"channel_details"`
	}
	if err := json.NewDecoder(res.Body).Decode(&consumers); err != nil {
		return nil, false
	}

	for _, c := range consumers {
		if c.Queue.Name == queue {
			conns = append(conns, c.ChannelDetails.ConnectionName)
		}
	}
	return conns, true
}

// closeConnection force-closes an AMQP connection through the RabbitMQ management API.
func closeConnection(adminPort int, name string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://127.0.0.1:%d/api/connections/%s", adminPort, url.PathEscape(name)), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth("user", "user")

	res, err := mgmtClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status %d closing connection %q", res.StatusCode, name)
	}
	return nil
}

func receiveWithin(t *testing.T, ch <-chan *message.Message, d time.Duration) *message.Message {
	t.Helper()

	select {
	case msg, ok := <-ch:
		require.True(t, ok, "subscriber channel was closed")
		return msg
	case <-time.After(d):
		require.FailNow(t, "no message received", "waited %s", d)
		return nil
	}
}

// An SSE stream must resume on its own when the broker connection drops. With AutoDelete the broker
// removes the queue as soon as the dropped connection's consumer goes away, so this verifies that
// watermill re-declares the same queue and keeps delivering on the original channel.
func TestEphemeralSubscriberResumesAfterConnectionLoss(t *testing.T) {
	cleanup, conf, adminPort, err := rabbitmq_test.RunRabbitMQDocker(false)
	require.NoError(t, err)
	defer cleanup()

	pub, err := NewAMQPPub(*conf, "resume-pub", helpers.SetupLogger(config.Info, "test", "resume-pub"))
	require.NoError(t, err)
	defer pub.Close()

	sub, err := NewAMQPEphemeralSub(*conf, "sse-resume", helpers.SetupLogger(config.Info, "test", "resume-sub"))
	require.NoError(t, err)
	defer sub.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	msgs, err := sub.Subscribe(ctx, "device.#")
	require.NoError(t, err)

	const queueName = "device.#_sse-resume"
	waitForQueue(t, adminPort, queueName)

	// Baseline: events flow before the connection is lost.
	var firstConns []string
	require.Eventually(t, func() bool {
		conns, ok := queueConsumerConnections(adminPort, queueName)
		firstConns = conns
		return ok && len(conns) == 1
	}, 30*time.Second, 500*time.Millisecond, "queue %q never reported its consumer", queueName)

	require.NoError(t, pub.Publish("device.before", message.NewMessage("before", []byte("before"))))
	got := receiveWithin(t, msgs, 15*time.Second)
	assert.Equal(t, "before", string(got.Payload))
	got.Ack()

	// Drop only the subscriber's connection (the publisher's is a different connection).
	oldConn := firstConns[0]
	require.NoError(t, closeConnection(adminPort, oldConn))

	// The subscriber must come back on a new connection and consume from the queue again.
	require.Eventually(t, func() bool {
		conns, ok := queueConsumerConnections(adminPort, queueName)
		if !ok || len(conns) != 1 {
			return false
		}
		return conns[0] != oldConn
	}, 60*time.Second, 500*time.Millisecond, "subscriber did not reconnect to queue %q after its connection was closed", queueName)
	status, q := getQueue(t, adminPort, queueName)
	require.Equal(t, http.StatusOK, status, "queue %q must exist again after the reconnect", queueName)
	assert.True(t, q.AutoDelete)

	// A new event reaches the same subscriber channel.
	require.NoError(t, pub.Publish("device.after", message.NewMessage("after", []byte("after"))))
	got = receiveWithin(t, msgs, 15*time.Second)
	assert.Equal(t, "after", string(got.Payload))
	got.Ack()
}
