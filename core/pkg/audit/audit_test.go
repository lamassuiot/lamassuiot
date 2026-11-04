package audit

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/require"
)

type auditPublisher struct {
	ctx     context.Context
	payload any
}

func (p *auditPublisher) PublishCloudEvent(ctx context.Context, payload any) {
	p.ctx, p.payload = ctx, payload
}

func TestAuditPublisherPublishesSuccessAndErrorRecords(t *testing.T) {
	publisher := &auditPublisher{}
	audit := NewAuditPublisher(publisher)
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyMatchedPrincipals, []string{"p1"})

	audit.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCAKey, "input", nil, "output")
	body := publisher.payload.(AuditBody)
	require.False(t, body.HasError)
	require.Equal(t, "audit.ca.create", publisher.ctx.Value(core.LamassuContextKeyEventType))
	require.Equal(t, []string{"p1"}, body.Principals)

	audit.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCAKey, "input", requireError{}, nil)
	body = publisher.payload.(AuditBody)
	require.True(t, body.HasError)
	require.Equal(t, "ca.create.error", publisher.ctx.Value(core.LamassuContextKeyEventType))
}

type requireError struct{}

func (requireError) Error() string { return "failed" }
