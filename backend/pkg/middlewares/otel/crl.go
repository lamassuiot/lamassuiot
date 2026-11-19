package auditpub

import (
	"context"
	"crypto/x509"

	beService "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type CRLOTelTracer struct {
	next        services.CRLService
	tracerName  string
	serviceName string
}

func NewCRLOTelTracer() beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &CRLOTelTracer{
			next:        next,
			tracerName:  "va-svc",
			serviceName: "VA",
		}
	}
}

func (mw *CRLOTelTracer) GetCRL(ctx context.Context, input services.GetCRLInput) (output *x509.RevocationList, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCRL(ctx, input)
}

func (mw *CRLOTelTracer) GetCRLSettings(ctx context.Context, input services.GetCRLSettingsInput) (output *models.CRLSettings, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCRLSettings(ctx, input)
}

func (mw *CRLOTelTracer) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCRLSettingsList(ctx, input)
}

func (mw *CRLOTelTracer) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (output *models.CRLSettings, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateCRLSettings(ctx, input)
}

func (mw *CRLOTelTracer) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.CalculateCRL(ctx, input)
}

func (mw *CRLOTelTracer) InitCRLSettings(ctx context.Context, caID string) (output *models.CRLSettings, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.InitCRLSettings(ctx, caID)
}
