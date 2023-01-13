package service

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	log "github.com/sirupsen/logrus"
)

type Middleware func(Service) Service

func LoggingMiddleware() Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next: next,
		}
	}
}

type loggingMiddleware struct {
	next Service
}

func (mw loggingMiddleware) Health() (output bool) {
	defer func(begin time.Time) {
		log.WithFields(log.Fields{
			"method": "Health",
			"took":   time.Since(begin),
		}).Trace(output)
	}(time.Now())
	return mw.next.Health()
}

func (mw loggingMiddleware) GetEngineProviderInfo() (output api.EngineProviderInfo) {
	defer func(begin time.Time) {
		log.WithFields(log.Fields{
			"method": "GetEngineProviderInfo",
			"output": output,
			"took":   time.Since(begin),
		}).Trace(fmt.Sprintf("output: %v", output))
	}(time.Now())
	return mw.next.GetEngineProviderInfo()
}

func (mw loggingMiddleware) Stats(ctx context.Context, input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "Stats"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.Stats(ctx, input)
}

func (mw loggingMiddleware) CreateCA(ctx context.Context, input *api.CreateCAInput) (output *api.CreateCAOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "CreateCA"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.CreateCA(ctx, input)
}

func (mw loggingMiddleware) GetCAs(ctx context.Context, input *api.GetCAsInput) (output *api.GetCAsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCAs"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCAs(ctx, input)
}

func (mw loggingMiddleware) GetCAByName(ctx context.Context, input *api.GetCAByNameInput) (output *api.GetCAByNameOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCAByName"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCAByName(ctx, input)
}

func (mw loggingMiddleware) RevokeCA(ctx context.Context, input *api.RevokeCAInput) (output *api.RevokeCAOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "RevokeCA"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.RevokeCA(ctx, input)
}

func (mw loggingMiddleware) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (output *api.UpdateCAStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateCAStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw loggingMiddleware) IterateCAsWithPredicate(ctx context.Context, input *api.IterateCAsWithPredicateInput) (output *api.IterateCAsWithPredicateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "IterateCAsWithPredicate"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %s", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.IterateCAsWithPredicate(ctx, input)
}
func (mw loggingMiddleware) SignCertificateRequest(ctx context.Context, input *api.SignCertificateRequestInput) (output *api.SignCertificateRequestOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "SignCertificateRequest"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.SignCertificateRequest(ctx, input)
}

func (mw loggingMiddleware) UpdateCertificateStatus(ctx context.Context, input *api.UpdateCertificateStatusInput) (output *api.UpdateCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateCertificateStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) RevokeCertificate(ctx context.Context, input *api.RevokeCertificateInput) (output *api.RevokeCertificateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "RevokeCertificate"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.RevokeCertificate(ctx, input)
}

func (mw loggingMiddleware) GetCertificateBySerialNumber(ctx context.Context, input *api.GetCertificateBySerialNumberInput) (output *api.GetCertificateBySerialNumberOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCertificateBySerialNumber"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCertificateBySerialNumber(ctx, input)
}

func (mw loggingMiddleware) IterateCertificatesWithPredicate(ctx context.Context, input *api.IterateCertificatesWithPredicateInput) (output *api.IterateCertificatesWithPredicateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "IterateCertificatesWithPredicate"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %s", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.IterateCertificatesWithPredicate(ctx, input)
}

func (mw loggingMiddleware) GetCertificates(ctx context.Context, input *api.GetCertificatesInput) (output *api.GetCertificatesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCertificates"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCertificates(ctx, input)
}

func (mw loggingMiddleware) GetCertificatesAboutToExpire(ctx context.Context, input *api.GetCertificatesAboutToExpireInput) (output *api.GetCertificatesAboutToExpireOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCertificatesAboutToExpire"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCertificatesAboutToExpire(ctx, input)
}

func (mw loggingMiddleware) GetExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.GetExpiredAndOutOfSyncCertificatesInput) (output *api.GetExpiredAndOutOfSyncCertificatesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetExpiredAndOutOfSyncCertificates"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetExpiredAndOutOfSyncCertificates(ctx, input)
}

func (mw loggingMiddleware) ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (output *api.ScanAboutToExpireCertificatesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "ScanAboutToExpireCertificates"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.ScanAboutToExpireCertificates(ctx, input)
}

func (mw loggingMiddleware) ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (output *api.ScanExpiredAndOutOfSyncCertificatesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "ScanExpiredAndOutOfSyncCertificates"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.ScanExpiredAndOutOfSyncCertificates(ctx, input)
}
