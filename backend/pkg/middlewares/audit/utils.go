package auditpub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type AuditBody struct {
	Input    interface{} `json:"input"`
	HasError bool        `json:"has_error"`
	Output   interface{} `json:"output"`
}

type AuditPublisher struct {
	eventpub.ICloudEventPublisher
}

func NewAuditPublisher(publisher eventpub.ICloudEventPublisher) *AuditPublisher {
	return &AuditPublisher{
		ICloudEventPublisher: publisher,
	}
}

func (audit *AuditPublisher) HandleServiceOutputAndPublishAuditRecord(ctx context.Context, eventType models.EventType, input interface{}, err error, output interface{}) {
	var auditBody AuditBody
	var auditEventType = fmt.Sprintf("audit.%s", eventType)

	if err != nil {
		auditEventType = fmt.Sprintf("%s.error", eventType)
		ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, auditEventType)

		auditBody = AuditBody{
			Input:    input,
			HasError: true,
			Output:   err.Error(),
		}
	} else {
		ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, auditEventType)
		auditBody = AuditBody{
			Input:    input,
			HasError: false,
			Output:   output,
		}
	}

	audit.PublishCloudEvent(ctx, auditBody)
}
