package eventbus

import (
	"context"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// markerSubscriber lets tests tell which subscriber factory a fake engine used.
type markerSubscriber struct{ name string }

func (m *markerSubscriber) Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error) {
	return nil, nil
}
func (m *markerSubscriber) Close() error { return nil }

type plainEngine struct{}

func (plainEngine) Subscriber() (message.Subscriber, error) {
	return &markerSubscriber{name: "plain"}, nil
}
func (plainEngine) Publisher() (message.Publisher, error) { return nil, nil }

type ephemeralEngine struct{ plainEngine }

func (ephemeralEngine) EphemeralSubscriber() (message.Subscriber, error) {
	return &markerSubscriber{name: "ephemeral"}, nil
}

func init() {
	eventbus.RegisterEventBusEngine("test-ephemeral", func(string, any, string, *logrus.Entry) (eventbus.EventBusEngine, error) {
		return ephemeralEngine{}, nil
	})
	eventbus.RegisterEventBusEngine("test-plain", func(string, any, string, *logrus.Entry) (eventbus.EventBusEngine, error) {
		return plainEngine{}, nil
	})
}

func TestEphemeralSubscriberUsesEngineSupport(t *testing.T) {
	logger, hook := test.NewNullLogger()

	sub, err := NewEventBusEphemeralSubscriber(cconfig.EventBusEngine{Provider: "test-ephemeral"}, "svc", logger.WithField("test", t.Name()))
	require.NoError(t, err)
	assert.Equal(t, "ephemeral", sub.(*markerSubscriber).name)
	assert.Empty(t, hook.AllEntries(), "no warning expected when the engine supports ephemeral subscribers")
}

func TestEphemeralSubscriberFallsBackToSubscriber(t *testing.T) {
	logger, hook := test.NewNullLogger()

	sub, err := NewEventBusEphemeralSubscriber(cconfig.EventBusEngine{Provider: "test-plain"}, "svc", logger.WithField("test", t.Name()))
	require.NoError(t, err)
	assert.Equal(t, "plain", sub.(*markerSubscriber).name)

	require.Len(t, hook.AllEntries(), 1)
	entry := hook.LastEntry()
	assert.Equal(t, logrus.WarnLevel, entry.Level)
	assert.Contains(t, entry.Message, "falling back to a regular subscriber")
}

func TestEphemeralSubscriberUnknownProvider(t *testing.T) {
	logger, _ := test.NewNullLogger()

	assert.NotPanics(t, func() {
		sub, err := NewEventBusEphemeralSubscriber(cconfig.EventBusEngine{Provider: "nope"}, "svc", logger.WithField("test", t.Name()))
		assert.Error(t, err)
		assert.Nil(t, sub)
	})
}
