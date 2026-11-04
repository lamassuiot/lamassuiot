package eventpub

import (
	"context"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type recordingPublisher struct {
	ctx     context.Context
	payload any
}

type cloudEventMessagePublisher struct {
	topic string
	msg   *message.Message
}

func (p *cloudEventMessagePublisher) Publish(topic string, messages ...*message.Message) error {
	p.topic, p.msg = topic, messages[0]
	return nil
}

func (p *cloudEventMessagePublisher) Close() error { return nil }

func TestCloudEventPublisherPublishesAndHandlesMarshalErrors(t *testing.T) {
	publisher := &cloudEventMessagePublisher{}
	logger := logrus.NewEntry(logrus.New())
	cloud := &CloudEventPublisher{Publisher: publisher, ServiceID: "test", Logger: logger}
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyEventType, "test.created")
	cloud.PublishCloudEvent(ctx, map[string]string{"value": "ok"})
	require.Equal(t, "test.created", publisher.topic)
	require.NotEmpty(t, publisher.msg.Payload)

	cloud.PublishCloudEvent(ctx, func() {})
	require.Equal(t, "test.created", publisher.topic)
}

func (p *recordingPublisher) PublishCloudEvent(ctx context.Context, payload any) {
	p.ctx, p.payload = ctx, payload
}

func TestEventPublisherWithSourceMiddleware(t *testing.T) {
	publisher := &recordingPublisher{}
	middleware := NewEventPublisherWithSourceMiddleware(publisher, "service/authz")
	middleware.PublishCloudEvent(context.Background(), "payload")
	require.Equal(t, "service/authz", publisher.ctx.Value(core.LamassuContextKeySource))
	require.Equal(t, "payload", publisher.payload)

	ctx := context.WithValue(context.Background(), core.LamassuContextKeySource, "service/ca")
	middleware.PublishCloudEvent(ctx, "other")
	require.Equal(t, "service/ca", publisher.ctx.Value(core.LamassuContextKeySource))
}
