package service

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
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

func (mw loggingMiddleware) Stats(ctx context.Context) (stats dto.Stats, scanDate time.Time) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Stats",
			"took", time.Since(begin),
			"stats", stats,
			"scan_date", scanDate,
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.Stats(ctx)
}

func (mw loggingMiddleware) PostDevice(ctx context.Context, alias string, deviceID string, DmsID string, description string, tags []string, iconName string, iconColor string) (deviceResp dto.Device, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PostDevice",
			"id", deviceID,
			"alias", alias,
			"dms id", DmsID,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.PostDevice(ctx, alias, deviceID, DmsID, description, tags, iconName, iconColor)
}

func (mw loggingMiddleware) GetDevices(ctx context.Context, queryParameters filters.QueryParameters) (deviceResp []dto.Device, length int, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDevices",
			"device_resp", len(deviceResp),
			"total_devices", length,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDevices(ctx, queryParameters)
}

func (mw loggingMiddleware) GetDeviceById(ctx context.Context, deviceId string) (deviceResp dto.Device, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceById",
			"device_id", deviceId,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceById(ctx, deviceId)
}

func (mw loggingMiddleware) UpdateDeviceById(ctx context.Context, alias string, deviceID string, DmsID string, description string, tags []string, iconName string, iconColor string) (deviceResp dto.Device, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateDeviceById",
			"device_id", deviceID,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.UpdateDeviceById(ctx, alias, deviceID, DmsID, description, tags, iconName, iconColor)
}

func (mw loggingMiddleware) GetDevicesByDMS(ctx context.Context, dmsId string, queryParameters filters.QueryParameters) (deviceResp []dto.Device, total_devices int, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDevicesByDMS",
			"dmsId", dmsId,
			"deviceResp", len(deviceResp),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDevicesByDMS(ctx, dmsId, queryParameters)
}

func (mw loggingMiddleware) DeleteDevice(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteDevice",
			"id", id,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.DeleteDevice(ctx, id)
}

func (mw loggingMiddleware) RevokeDeviceCert(ctx context.Context, id string, revocationReason string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "RevokeDeviceCert",
			"revocationReason", revocationReason,
			"id", id,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.RevokeDeviceCert(ctx, id, revocationReason)
}

func (mw loggingMiddleware) GetDeviceLogs(ctx context.Context, id string, queryParameters filters.QueryParameters) (logs []dto.DeviceLog, total_logs int, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceLogs",
			"id", id,
			"logs", len(logs),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceLogs(ctx, id, queryParameters)
}

func (mw loggingMiddleware) GetDeviceCert(ctx context.Context, id string) (cert dto.DeviceCert, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceCert",
			"id", id,
			"cert_CommonName", cert.Subject.CommonName,
			"cert_SerialNumber", cert.SerialNumber,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceCert(ctx, id)
}

func (mw loggingMiddleware) GetDeviceCertHistory(ctx context.Context, id string) (histo []dto.DeviceCertHistory, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDeviceCertHistory",
			"id", id,
			"histo", len(histo),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDeviceCertHistory(ctx, id)
}
func (mw loggingMiddleware) GetDmsCertHistoryThirtyDays(ctx context.Context, queryParameters filters.QueryParameters) (certHisto []dto.DMSCertHistory, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDmsCertHistoryThirtyDays",
			"histo", len(certHisto),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDmsCertHistoryThirtyDays(ctx, queryParameters)
}
func (mw loggingMiddleware) GetDmsLastIssuedCert(ctx context.Context, queryParameters filters.QueryParameters) (dmsLastIssued []dto.DMSLastIssued, total_issued int, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDmsLastIssuedCert",
			"dmsLastIssued", len(dmsLastIssued),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDmsLastIssuedCert(ctx, queryParameters)
}
