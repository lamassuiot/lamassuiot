package service

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"

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

func (mw *instrumentingMiddleware) CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dms dto.DMS, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateDMS", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.CreateDMS(ctx, csrBase64Encoded, dmsName)
}

func (mw *instrumentingMiddleware) CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (_ string, d dto.DMS, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateDMSForm", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.CreateDMSForm(ctx, subject, PrivateKeyMetadata, dmsName)
}

func (mw *instrumentingMiddleware) UpdateDMSStatus(ctx context.Context, status string, id string, CAList []string) (dOut dto.DMS, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "UpdateDMSStatus", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.UpdateDMSStatus(ctx, status, id, CAList)
}

func (mw *instrumentingMiddleware) DeleteDMS(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "DeleteDMS", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.DeleteDMS(ctx, id)
}

func (mw *instrumentingMiddleware) GetDMSs(ctx context.Context) (d []dto.DMS, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDMSs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDMSs(ctx)
}
func (mw *instrumentingMiddleware) GetDMSbyID(ctx context.Context, id string) (d dto.DMS, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDMSbyID", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDMSbyID(ctx, id)
}
