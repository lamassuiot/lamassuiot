package service

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/jinzhu/copier"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/opentracing/opentracing-go"
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

func (mw loggingMiddleware) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (output *api.CreateDMSOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		var outputCopy api.CreateDMSOutput // Clone output to hide private key
		copier.Copy(&outputCopy, output)

		logMsg = append(logMsg, "method", "CreateDMS")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			outputCopy.PrivateKey = "***"
			logMsg = append(logMsg, "output", outputCopy.Serialize())
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.CreateDMS(ctx, input)
}

func (mw loggingMiddleware) CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (output *api.CreateDMSWithCertificateRequestOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "CreateDMSWithCertificateRequest")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.Serialize())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.CreateDMSWithCertificateRequest(ctx, input)
}

func (mw loggingMiddleware) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (output *api.UpdateDMSStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateDMSStatus")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.Serialize())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.UpdateDMSStatus(ctx, input)
}

func (mw loggingMiddleware) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (output *api.UpdateDMSAuthorizedCAsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateDMSAuthorizedCAs")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.Serialize())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.UpdateDMSAuthorizedCAs(ctx, input)
}

func (mw loggingMiddleware) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (output *api.GetDMSsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetDMSs")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.Serialize())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.GetDMSs(ctx, input)
}

func (mw loggingMiddleware) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (output *api.GetDMSByNameOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetDMSByName")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "output", output.Serialize())
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.GetDMSByName(ctx, input)
}
