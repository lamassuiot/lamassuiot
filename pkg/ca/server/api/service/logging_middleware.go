package service

import (
	"context"
	"time"

	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
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

func (mw loggingMiddleware) Health() bool {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.Health()
}

func (mw loggingMiddleware) GetEngineProviderInfo() (output api.EngineProviderInfo) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetEngineProviderInfo",
			"output", output,
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.GetEngineProviderInfo()
}

func (mw loggingMiddleware) Stats(ctx context.Context, input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "Stats")
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
	return mw.next.Stats(ctx, input)
}

func (mw loggingMiddleware) CreateCA(ctx context.Context, input *api.CreateCAInput) (output *api.CreateCAOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "CreateCA")
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
	return mw.next.CreateCA(ctx, input)
}

func (mw loggingMiddleware) GetCAs(ctx context.Context, input *api.GetCAsInput) (output *api.GetCAsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCAs")
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
	return mw.next.GetCAs(ctx, input)
}

func (mw loggingMiddleware) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (output *api.GetCAByNameOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCAByName")
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
	return mw.next.GetCAByName(ctx, input)
}

func (mw loggingMiddleware) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (output *api.RevokeCAOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "RevokeCA")
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
	return mw.next.RevokeCA(ctx, input)
}

func (mw loggingMiddleware) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (output *api.UpdateCAStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateCAStatus")
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
	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw loggingMiddleware) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (output *api.IterateCAsWithPredicateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "IterateCAsWithPredicate")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.IterateCAsWithPredicate(ctx, input)
}
func (mw loggingMiddleware) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (output *api.SignCertificateRequestOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "SignCertificateRequest")
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
	return mw.next.SignCertificateRequest(ctx, input)
}

func (mw loggingMiddleware) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (output *api.UpdateCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateCertificateStatus")
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
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (output *api.RevokeCertificateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "RevokeCertificate")
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
	return mw.next.RevokeCertificate(ctx, input)
}

func (mw loggingMiddleware) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (output *api.GetCertificateBySerialNumberOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCertificateBySerialNumber")
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
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw loggingMiddleware) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (output *api.IterateCertificatesWithPredicateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "IterateCertificatesWithPredicate")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.IterateCertificatesWithPredicate(ctx, input)
}

func (mw loggingMiddleware) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (output *api.GetCertificatesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCertificates")
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
	return mw.next.GetCertificates(ctx, input)
}
