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
)

type CAOTelTracer struct {
	next        services.CAService
	tracerName  string
	serviceName string
}

func NewCAOTelTracer() lservices.CAMiddleware {
	return func(next services.CAService) services.CAService {
		return &CAOTelTracer{
			next:        next,
			tracerName:  "ca-svc",
			serviceName: "CA",
		}
	}
}

func (mw CAOTelTracer) GetStats(ctx context.Context, input services.GetStatsInput) (*models.CAStats, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetStats(ctx, input)
}

func (mw CAOTelTracer) GetStatsByCAID(ctx context.Context, input services.GetStatsByCAIDInput) (map[models.CertificateStatus]int, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetStatsByCAID(ctx, input)
}

func (mw CAOTelTracer) CreateCA(ctx context.Context, input services.CreateCAInput) (output *models.CACertificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.CreateCA(ctx, input)
}

func (mw CAOTelTracer) ImportCA(ctx context.Context, input services.ImportCAInput) (output *models.CACertificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.ImportCA(ctx, input)
}

func (mw CAOTelTracer) GetCAByID(ctx context.Context, input services.GetCAByIDInput) (*models.CACertificate, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCAByID(ctx, input)
}

func (mw CAOTelTracer) GetCAs(ctx context.Context, input services.GetCAsInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCAs(ctx, input)
}

func (mw CAOTelTracer) GetCAsByCommonName(ctx context.Context, input services.GetCAsByCommonNameInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCAsByCommonName(ctx, input)
}

func (mw CAOTelTracer) UpdateCAStatus(ctx context.Context, input services.UpdateCAStatusInput) (output *models.CACertificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw CAOTelTracer) UpdateCAProfile(ctx context.Context, input services.UpdateCAProfileInput) (output *models.CACertificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateCAProfile(ctx, input)
}

func (mw CAOTelTracer) UpdateCAMetadata(ctx context.Context, input services.UpdateCAMetadataInput) (output *models.CACertificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateCAMetadata(ctx, input)
}

func (mw CAOTelTracer) DeleteCA(ctx context.Context, input services.DeleteCAInput) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.DeleteCA(ctx, input)
}

func (mw CAOTelTracer) ReissueCA(ctx context.Context, input services.ReissueCAInput) (*models.CACertificate, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.ReissueCA(ctx, input)
}

func (mw CAOTelTracer) SignCertificate(ctx context.Context, input services.SignCertificateInput) (output *models.Certificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.SignCertificate(ctx, input)
}

func (mw CAOTelTracer) ImportCertificate(ctx context.Context, input services.ImportCertificateInput) (output *models.Certificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.ImportCertificate(ctx, input)
}

func (mw CAOTelTracer) SignatureSign(ctx context.Context, input services.SignatureSignInput) (output []byte, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.SignatureSign(ctx, input)
}

func (mw CAOTelTracer) SignatureVerify(ctx context.Context, input services.SignatureVerifyInput) (output bool, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.SignatureVerify(ctx, input)
}

func (mw CAOTelTracer) GetCertificateBySerialNumber(ctx context.Context, input services.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw CAOTelTracer) GetCertificates(ctx context.Context, input services.GetCertificatesInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCertificates(ctx, input)
}

func (mw CAOTelTracer) GetCertificatesByCA(ctx context.Context, input services.GetCertificatesByCAInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCertificatesByCA(ctx, input)
}

func (mw CAOTelTracer) GetCertificatesByExpirationDate(ctx context.Context, input services.GetCertificatesByExpirationDateInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCertificatesByExpirationDate(ctx, input)
}

func (mw CAOTelTracer) UpdateCertificateStatus(ctx context.Context, input services.UpdateCertificateStatusInput) (output *models.Certificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw CAOTelTracer) GetCertificatesByCaAndStatus(ctx context.Context, input services.GetCertificatesByCaAndStatusInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCertificatesByCaAndStatus(ctx, input)
}

func (mw CAOTelTracer) GetCertificatesByStatus(ctx context.Context, input services.GetCertificatesByStatusInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetCertificatesByStatus(ctx, input)
}

func (mw CAOTelTracer) UpdateCertificateMetadata(ctx context.Context, input services.UpdateCertificateMetadataInput) (output *models.Certificate, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateCertificateMetadata(ctx, input)
}

func (mw CAOTelTracer) DeleteCertificate(ctx context.Context, input services.DeleteCertificateInput) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.DeleteCertificate(ctx, input)
}

func (mw CAOTelTracer) GetIssuanceProfiles(ctx context.Context, input services.GetIssuanceProfilesInput) (string, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetIssuanceProfiles(ctx, input)
}

func (mw CAOTelTracer) GetIssuanceProfileByID(ctx context.Context, input services.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.GetIssuanceProfileByID(ctx, input)
}

func (mw CAOTelTracer) CreateIssuanceProfile(ctx context.Context, input services.CreateIssuanceProfileInput) (output *models.IssuanceProfile, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.CreateIssuanceProfile(ctx, input)
}

func (mw CAOTelTracer) UpdateIssuanceProfile(ctx context.Context, input services.UpdateIssuanceProfileInput) (output *models.IssuanceProfile, err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.UpdateIssuanceProfile(ctx, input)
}

func (mw CAOTelTracer) DeleteIssuanceProfile(ctx context.Context, input services.DeleteIssuanceProfileInput) (err error) {
	ctx, span := otel.GetTracerProvider().Tracer(mw.tracerName).Start(ctx, sdk.GetCallerFunctionName(), trace.WithAttributes(semconv.ServiceName(mw.serviceName)))
	defer span.End()

	return mw.next.DeleteIssuanceProfile(ctx, input)
}
