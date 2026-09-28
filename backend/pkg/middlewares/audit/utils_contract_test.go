package auditpub

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/stretchr/testify/require"
)

type auditPayloadPublisher struct {
	payload interface{}
	ctx     context.Context
}

func auditTestContext() context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-test",
		TenantID:       "tenant-test",
		ActorID:        "actor-test",
		ActorType:      "test",
		CorrelationID:  "correlation-test",
		Source:         "audit-test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func (publisher *auditPayloadPublisher) PublishCloudEvent(ctx context.Context, payload interface{}) {
	publisher.ctx = ctx
	publisher.payload = payload
}

var _ eventpub.ICloudEventPublisher = (*auditPayloadPublisher)(nil)

func TestAuditBodyContainsStructuredTenantContract(t *testing.T) {
	publisher := &auditPayloadPublisher{}
	audit := NewAuditPublisher(publisher)
	ctx := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-a",
		TenantID:       "tenant-a",
		ActorID:        "actor-a",
		ActorType:      "user",
		CorrelationID:  "corr-a",
		Source:         "http-api",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, "ca/ca-a")

	audit.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCAKey, map[string]string{"private_key": "do-not-record"}, core.ErrTenantResourceAccessDenied, map[string]string{"token": "do-not-record"})

	body, ok := publisher.payload.(AuditBody)
	require.True(t, ok)
	require.Equal(t, "org-a", body.OrganizationID)
	require.Equal(t, "tenant-a", body.TenantID)
	require.Equal(t, "actor-a", body.ActorID)
	require.Equal(t, "user", body.ActorType)
	require.Equal(t, "corr-a", body.CorrelationID)
	require.Equal(t, string(models.EventCreateCAKey), body.Action)
	require.Equal(t, "rejected", body.Result)
	require.Equal(t, "http-api", body.Origin)
	require.Equal(t, "ca/ca-a", body.Resource)
	require.True(t, body.HasError)
	require.False(t, body.Timestamp.IsZero())
	require.True(t, body.Input.Present)
	require.True(t, body.Output.Present)
	serialized, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), "do-not-record")
	require.NotContains(t, string(serialized), "private_key")
	require.NotContains(t, string(serialized), "token")
}
