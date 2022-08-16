package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
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

func (mw *instrumentingMiddleware) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (output *api.CreateDMSOutput, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateDMS", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.CreateDMS(ctx, input)
}

func (mw *instrumentingMiddleware) CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (output *api.CreateDMSWithCertificateRequestOutput, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "CreateDMSWithCertificateRequest", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.CreateDMSWithCertificateRequest(ctx, input)
}

func (mw *instrumentingMiddleware) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (output *api.UpdateDMSStatusOutput, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "UpdateDMSStatus", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.UpdateDMSStatus(ctx, input)
}

func (mw *instrumentingMiddleware) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (output *api.UpdateDMSAuthorizedCAsOutput, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "UpdateDMSAuthorizedCAs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.UpdateDMSAuthorizedCAs(ctx, input)
}

func (mw *instrumentingMiddleware) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (output *api.GetDMSsOutput, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDMSs", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDMSs(ctx, input)
}

func (mw *instrumentingMiddleware) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (output *api.GetDMSByNameOutput, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetDMSByName", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetDMSByName(ctx, input)
}
