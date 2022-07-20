package service

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	"github.com/go-kit/kit/metrics"
)

type instrumentingMiddleware struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	next           Service
}

func NewInstrumentingMiddleware(counter metrics.Counter, latency metrics.Histogram) Middleware {
	return func(next Service) Service {
		return &instrumentingMiddleware{
			requestCount:   counter,
			requestLatency: latency,
			next:           next,
		}
	}
}

func (mw *instrumentingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", "Health", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.Health(ctx)
}
func (mw instrumentingMiddleware) Stats(ctx context.Context) (stats dto.Stats, scanDate time.Time) {
	defer func(begin time.Time) {
		lvs := []string{"method", "Stats", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.Stats(ctx)
}

func (mw *instrumentingMiddleware) PostDevice(ctx context.Context, alias string, deviceID string, DmsID string, description string, tags []string, iconName string, iconColor string) (deviceResp dto.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "PostDevice", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.PostDevice(ctx, alias, deviceID, DmsID, description, tags, iconName, iconColor)
}

func (mw *instrumentingMiddleware) GetDevices(ctx context.Context, queryParameters filters.QueryParameters) (device []dto.Device, length int, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDevices", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDevices(ctx, queryParameters)
}

func (mw *instrumentingMiddleware) GetDeviceById(ctx context.Context, deviceId string) (device dto.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceById", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceById(ctx, deviceId)
}
func (mw *instrumentingMiddleware) UpdateDeviceById(ctx context.Context, alias string, deviceID string, DmsID string, description string, tags []string, iconName string, iconColor string) (deviceResp dto.Device, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "UpdateDeviceById", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.UpdateDeviceById(ctx, alias, deviceID, DmsID, description, tags, iconName, iconColor)
}

func (mw *instrumentingMiddleware) GetDevicesByDMS(ctx context.Context, dmsId string, queryParameters filters.QueryParameters) (devices []dto.Device, total_devices int, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDevicesByDMS", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDevicesByDMS(ctx, dmsId, queryParameters)
}
func (mw *instrumentingMiddleware) DeleteDevice(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteDevice", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteDevice(ctx, id)
}
func (mw *instrumentingMiddleware) RevokeDeviceCert(ctx context.Context, id string, revocationReason string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "RevokeDeviceCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.RevokeDeviceCert(ctx, id, revocationReason)
}
func (mw *instrumentingMiddleware) GetDeviceLogs(ctx context.Context, id string, queryParameters filters.QueryParameters) (logs []dto.DeviceLog, total_logs int, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceLogs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceLogs(ctx, id, queryParameters)
}
func (mw *instrumentingMiddleware) GetDeviceCert(ctx context.Context, id string) (cert dto.DeviceCert, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceCert(ctx, id)
}
func (mw *instrumentingMiddleware) GetDeviceCertHistory(ctx context.Context, id string) (history []dto.DeviceCertHistory, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDeviceCertHistory", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDeviceCertHistory(ctx, id)
}
func (mw *instrumentingMiddleware) GetDmsCertHistoryThirtyDays(ctx context.Context, queryParameters filters.QueryParameters) (history []dto.DMSCertHistory, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDmsCertHistoryThirtyDays", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDmsCertHistoryThirtyDays(ctx, queryParameters)
}
func (mw *instrumentingMiddleware) GetDmsLastIssuedCert(ctx context.Context, queryParameters filters.QueryParameters) (dmsLastIssued []dto.DMSLastIssued, total_issued int, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDmsLastIssuedCert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDmsLastIssuedCert(ctx, queryParameters)
}
