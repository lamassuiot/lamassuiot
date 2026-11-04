package eventbus

import (
	"errors"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	coreeventbus "github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type testPublisher struct {
	err      error
	closed   bool
	topic    string
	messages []*message.Message
}

func (p *testPublisher) Publish(topic string, messages ...*message.Message) error {
	p.topic, p.messages = topic, messages
	return p.err
}

func (p *testPublisher) Close() error {
	p.closed = true
	return nil
}

func TestMessageMetadataCarrier(t *testing.T) {
	metadata := message.Metadata{}
	carrier := messageMetadataCarrier{metadata: metadata}
	carrier.Set("trace", "value")
	require.Equal(t, "value", carrier.Get("trace"))
	require.Contains(t, carrier.Keys(), "trace")
}

func TestOtelPublisherDecorator(t *testing.T) {
	underlying := &testPublisher{}
	decorator := &otelPublisherDecorator{pub: underlying}
	require.NoError(t, decorator.Publish("topic"))

	msg := message.NewMessage("id", []byte("body"))
	require.NoError(t, decorator.Publish("topic", msg))
	require.Equal(t, "topic", underlying.topic)
	require.Len(t, underlying.messages, 1)
	require.NotNil(t, msg.Context())

	require.NoError(t, decorator.Close())
	require.True(t, underlying.closed)

	failing := &otelPublisherDecorator{pub: &testPublisher{err: errors.New("publish failed")}}
	require.EqualError(t, failing.Publish("topic", msg), "publish failed")
}

func TestEventBusConstructorsUseRegisteredEngine(t *testing.T) {
	coreeventbus.RegisterEventBusEngine("test-pubsub", func(string, any, string, *logrus.Entry) (coreeventbus.EventBusEngine, error) {
		return &testEngine{}, nil
	})
	conf := cconfig.EventBusEngine{Provider: "test-pubsub"}
	subscriber, err := NewEventBusSubscriber(conf, "service", logrus.NewEntry(logrus.New()))
	require.NoError(t, err)
	require.Nil(t, subscriber)
	publisher, err := NewEventBusPublisher(conf, "service", logrus.NewEntry(logrus.New()))
	require.NoError(t, err)
	require.NotNil(t, publisher)
}

type testEngine struct{}

func (*testEngine) Subscriber() (message.Subscriber, error) { return nil, nil }
func (*testEngine) Publisher() (message.Publisher, error)   { return &testPublisher{}, nil }
