package eventpub

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type captureMessagePublisher struct {
	topics   []string
	messages []*message.Message
}

func (publisher *captureMessagePublisher) Publish(topic string, messages ...*message.Message) error {
	publisher.topics = append(publisher.topics, topic)
	publisher.messages = append(publisher.messages, messages...)
	return nil
}

func (publisher *captureMessagePublisher) Close() error {
	return nil
}

func TestCloudEventPublisherBuildsTenantEnvelope(t *testing.T) {
	messagePublisher := &captureMessagePublisher{}
	cloudEventPublisher := &CloudEventPublisher{
		Publisher: messagePublisher,
		Logger:    logrus.NewEntry(logrus.New()),
	}
	ctx := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-a",
		TenantID:       "tenant-a",
		ActorID:        "actor-a",
		ActorType:      "user",
		CorrelationID:  "correlation-a",
		Source:         "http-api",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, "certificate.create")

	cloudEventPublisher.PublishCloudEvent(ctx, map[string]string{"id": "cert-a"})

	require.Len(t, messagePublisher.messages, 1)
	require.Equal(t, []string{"certificate.create"}, messagePublisher.topics)
	var payload json.RawMessage
	require.NoError(t, json.Unmarshal(messagePublisher.messages[0].Payload, &payload))
	cloudEvent, err := helpers.ParseCloudEvent(payload)
	require.NoError(t, err)
	tenantContext, err := helpers.TenantContextFromCloudEvent(cloudEvent)
	require.NoError(t, err)
	require.Equal(t, "tenant-a", tenantContext.TenantID)
	require.Equal(t, "org-a", tenantContext.OrganizationID)
	require.Equal(t, "correlation-a", tenantContext.CorrelationID)
}
