package service

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
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

func (mw loggingMiddleware) CreateDMS(ctx context.Context, csrBase64Encoded string, dmsName string) (dms dto.DMS, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateDMS",
			"dmsName", dmsName,
			"dmsID", dms.Id,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.CreateDMS(ctx, csrBase64Encoded, dmsName)
}

func (mw loggingMiddleware) CreateDMSForm(ctx context.Context, subject dto.Subject, PrivateKeyMetadata dto.PrivateKeyMetadata, dmsName string) (_ string, d dto.DMS, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "CreateDMSForm",
			"dmsName", dmsName,
			"subject", subject,
			"KeyMetadata", PrivateKeyMetadata,
			"dmsID", d.Id,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.CreateDMSForm(ctx, subject, PrivateKeyMetadata, dmsName)
}

func (mw loggingMiddleware) UpdateDMSStatus(ctx context.Context, status string, id string, CAList []string) (dOut dto.DMS, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "UpdateDMSStatus",
			"id", id,
			"status", status,
			"dms_out", dOut,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.UpdateDMSStatus(ctx, status, id, CAList)
}

func (mw loggingMiddleware) DeleteDMS(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "DeleteDMS",
			"id", id,
			"err", err,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
		)
	}(time.Now())
	return mw.next.DeleteDMS(ctx, id)
}

func (mw loggingMiddleware) GetDMSs(ctx context.Context, queryParameters filters.QueryParameters) (d []dto.DMS, total_dmss int, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDMSs",
			"dmss", len(d),
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDMSs(ctx, queryParameters)
}
func (mw loggingMiddleware) GetDMSbyID(ctx context.Context, id string) (d dto.DMS, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetDMSbyID",
			"dms_name", d.Name,
			"dms_id", d.Id,
			"dms_cert_SerialNumber", d.SerialNumber,
			"dms_Authorized_CAs", d.AuthorizedCAs,
			"dms_status", d.Status,
			"took", time.Since(begin),
			"trace_id", opentracing.SpanFromContext(ctx),
			"err", err,
		)
	}(time.Now())
	return mw.next.GetDMSbyID(ctx, id)
}
