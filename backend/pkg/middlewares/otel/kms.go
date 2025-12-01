package auditpub

import (
	"context"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/metric"
)

type KMSOTelTracer struct {
	next        services.KMSService
	tracerName  string
	serviceName string
	metrics     *sdk.Metrics
}

func NewKMSOTelTracer() lservices.KMSMiddleware {
	return func(next services.KMSService) services.KMSService {
		metrics, _ := sdk.NewMetrics("KMS")

		return &KMSOTelTracer{
			next:        next,
			tracerName:  "kms-svc",
			serviceName: "KMS",
			metrics:     metrics,
		}
	}
}

func (mw KMSOTelTracer) GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCryptoEngineProvider(ctx)
}

func (mw KMSOTelTracer) GetKeys(ctx context.Context, input services.GetKeysInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetKeys(ctx, input)
}

func (mw KMSOTelTracer) GetKey(ctx context.Context, input services.GetKeyInput) (*models.Key, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetKey(ctx, input)
}

func (mw KMSOTelTracer) CreateKey(ctx context.Context, input services.CreateKeyInput) (output *models.Key, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	mw.metrics.MemoryUsage.Record(
		ctx,
		int64(sdk.GetMemoryUsage()),
		metric.WithAttributes(
			semconv.ServiceName(mw.serviceName),
			semconv.CodeFunction(sdk.GetCallerFunctionName()),
		),
	)


	return mw.next.CreateKey(ctx, input)
}

func (mw KMSOTelTracer) UpdateKeyMetadata(ctx context.Context, input services.UpdateKeyMetadataInput) (output *models.Key, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateKeyMetadata(ctx, input)
}

func (mw KMSOTelTracer) UpdateKeyAliases(ctx context.Context, input services.UpdateKeyAliasesInput) (output *models.Key, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateKeyAliases(ctx, input)
}

func (mw KMSOTelTracer) UpdateKeyName(ctx context.Context, input services.UpdateKeyNameInput) (output *models.Key, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateKeyName(ctx, input)
}

func (mw KMSOTelTracer) UpdateKeyTags(ctx context.Context, input services.UpdateKeyTagsInput) (output *models.Key, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateKeyTags(ctx, input)
}

func (mw KMSOTelTracer) DeleteKeyByID(ctx context.Context, input services.GetKeyInput) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.DeleteKeyByID(ctx, input)
}

func (mw KMSOTelTracer) SignMessage(ctx context.Context, input services.SignMessageInput) (output *models.MessageSignature, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.SignMessage(ctx, input)
}

func (mw KMSOTelTracer) VerifySignature(ctx context.Context, input services.VerifySignInput) (output *models.MessageValidation, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.VerifySignature(ctx, input)
}

func (mw KMSOTelTracer) ImportKey(ctx context.Context, input services.ImportKeyInput) (output *models.Key, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.ImportKey(ctx, input)
}
