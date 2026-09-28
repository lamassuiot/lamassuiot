package auditpub

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type AuditValueSummary struct {
	Present bool   `json:"present"`
	Type    string `json:"type,omitempty"`
}

type AuditBody struct {
	OrganizationID string            `json:"organization_id"`
	TenantID       string            `json:"tenant_id"`
	ActorID        string            `json:"actor_id"`
	ActorType      string            `json:"actor_type"`
	CorrelationID  string            `json:"correlation_id"`
	Action         string            `json:"action"`
	Result         string            `json:"result"`
	Origin         string            `json:"origin"`
	Resource       string            `json:"resource,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
	Input          AuditValueSummary `json:"input"`
	HasError       bool              `json:"has_error"`
	Output         AuditValueSummary `json:"output"`
}

type AuditPublisher struct {
	eventpub.ICloudEventPublisher
	Logger *logrus.Entry
}

func NewAuditPublisher(publisher eventpub.ICloudEventPublisher, logger ...*logrus.Entry) *AuditPublisher {
	var auditLogger *logrus.Entry
	if len(logger) > 0 {
		auditLogger = logger[0]
	}
	return &AuditPublisher{
		ICloudEventPublisher: publisher,
		Logger:               auditLogger,
	}
}

func (audit *AuditPublisher) HandleServiceOutputAndPublishAuditRecord(ctx context.Context, eventType models.EventType, input interface{}, err error, output interface{}) {
	tenantContext, contextErr := core.RequireTenantContext(ctx)
	if contextErr != nil {
		if audit.Logger != nil {
			audit.Logger.Errorf("cannot publish tenant audit event without a valid tenant context: %s", contextErr)
		}
		return
	}

	result := "success"
	auditEventType := fmt.Sprintf("audit.%s", eventType)
	if err != nil {
		result = "error"
		auditEventType = fmt.Sprintf("%s.error", eventType)
		var apiError errs.APIError
		if errors.As(err, &apiError) {
			status, _ := apiError.APIError()
			if status >= 400 && status < 500 {
				result = "rejected"
			}
		}
		if errors.Is(err, core.ErrTenantResourceAccessDenied) ||
			errors.Is(err, core.ErrTenantContextRequired) ||
			errors.Is(err, core.ErrTenantContextInvalid) {
			result = "rejected"
		}
	}
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, auditEventType)
	resource, _ := ctx.Value(core.LamassuContextKeyEventSubject).(string)
	auditBody := AuditBody{
		OrganizationID: tenantContext.OrganizationID,
		TenantID:       tenantContext.TenantID,
		ActorID:        tenantContext.ActorID,
		ActorType:      tenantContext.ActorType,
		CorrelationID:  tenantContext.CorrelationID,
		Action:         string(eventType),
		Result:         result,
		Origin:         tenantContext.Source,
		Resource:       resource,
		Timestamp:      time.Now().UTC(),
		Input:          summarizeAuditValue(input),
		HasError:       err != nil,
		Output:         summarizeAuditValue(output),
	}
	audit.PublishCloudEvent(ctx, auditBody)
}

func summarizeAuditValue(value interface{}) AuditValueSummary {
	if value == nil {
		return AuditValueSummary{}
	}
	return AuditValueSummary{Present: true, Type: reflect.TypeOf(value).String()}
}
