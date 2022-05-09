package service

import (
	"context"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/log"
	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
)

type Middleware func(Service) Service

func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger log.Logger
}

func (mw loggingMiddleware) Health(ctx context.Context) (healthy bool) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
			"healthy", healthy,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) GetCloudConnectors(ctx context.Context) (cloudconnectors []cloudproviders.CloudConnector, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCloudConnectors",
			"took", time.Since(begin),
			"number_cloud_connectors", len(cloudconnectors),
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.GetCloudConnectors(ctx)
}

func (mw loggingMiddleware) SynchronizeCA(ctx context.Context, cloudConnectorID string, caName string, enabledTs time.Time) (cloudConnector cloudproviders.CloudConnector, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "SynchronizeCA",
			"took", time.Since(begin),
			"cloud_connector_id", cloudConnectorID,
			"ca_name", caName,
			"enabled_ts", enabledTs,
			"cloud_connector", cloudConnector,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.SynchronizeCA(ctx, cloudConnectorID, caName, enabledTs)
}

func (mw loggingMiddleware) HandleCreateCAEvent(ctx context.Context, caName string, caSerialNumber string, caCertificate string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "HandleCreateCAEvent",
			"took", time.Since(begin),
			"ca_name", caName,
			"ca_serial_number", caSerialNumber,
			"ca_certificate", caCertificate,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.HandleCreateCAEvent(ctx, caName, caSerialNumber, caCertificate)
}
func (mw loggingMiddleware) HandleUpdateCaStatusEvent(ctx context.Context, caName string, status string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "HandleDeleteCAEvent",
			"took", time.Since(begin),
			"ca_name", caName,
			"status", status,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.HandleUpdateCaStatusEvent(ctx, caName, status)
}
func (mw loggingMiddleware) HandleUpdateCertStatusEvent(ctx context.Context, caName string, certSerialNumber string, status string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "HandleUpdateCertStatusEvent",
			"took", time.Since(begin),
			"ca_name", caName,
			"cert_serial_number", certSerialNumber,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.HandleUpdateCertStatusEvent(ctx, caName, certSerialNumber, status)
}
func (mw loggingMiddleware) UpdateSecurityAccessPolicy(ctx context.Context, cloudConnectorID string, caName string, serializedSecurityAccessPolicy string) (cloudConnector cloudproviders.CloudConnector, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateSecurityAccessPolicy",
			"took", time.Since(begin),
			"cloud_connector_id", cloudConnectorID,
			"ca_name", caName,
			"serialized_security_access_policy", serializedSecurityAccessPolicy,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.UpdateSecurityAccessPolicy(ctx, cloudConnectorID, caName, serializedSecurityAccessPolicy)
}
func (mw loggingMiddleware) UpdateCertStatus(ctx context.Context, deviceID string, certSerialNumber string, status string, connectorID string, caName string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateCertStatus",
			"took", time.Since(begin),
			"cloud_connector_id", connectorID,
			"cert_serialNumber", certSerialNumber,
			"device_id", deviceID,
			"status", status,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.UpdateCertStatus(ctx, deviceID, certSerialNumber, status, connectorID, caName)
}
func (mw loggingMiddleware) GetCloudConnectorByID(ctx context.Context, cloudConnectorID string) (connector cloudproviders.CloudConnector, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetCloudConnectorByID",
			"took", time.Since(begin),
			"cloud_connector_id", cloudConnectorID,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.GetCloudConnectorByID(ctx, cloudConnectorID)
}

func (mw loggingMiddleware) GetDeviceConfiguration(ctx context.Context, cloudConnectorID string, deviceID string) (deviceConfig interface{}, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceConfiguration",
			"took", time.Since(begin),
			"device_id", deviceID,
			"device", deviceConfig,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.GetDeviceConfiguration(ctx, cloudConnectorID, deviceID)
}
func (mw loggingMiddleware) UpdateCaStatus(ctx context.Context, caName string, status string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateCertStatus",
			"took", time.Since(begin),
			"ca_name", caName,
			"status", status,
			"error", err,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.UpdateCaStatus(ctx, caName, status)
}
