package auditpub

import (
	"context"
	"crypto/x509"

	beService "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
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

func (mw *CRLOTelTracer) GetVARole(ctx context.Context, input services.GetVARoleInput) (output *models.VARole, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetVARole(ctx, input)
}

func (mw *CRLOTelTracer) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetVARoles(ctx, input)
}

func (mw *CRLOTelTracer) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (output *models.VARole, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateVARole(ctx, input)
}

func (mw *CRLOTelTracer) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.CalculateCRL(ctx, input)
}

func (mw *CRLOTelTracer) InitCRLRole(ctx context.Context, caSKI string) (output *models.VARole, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.InitCRLRole(ctx, caSKI)
}
