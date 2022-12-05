package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jinzhu/copier"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
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

func (mw loggingMiddleware) Health(ctx context.Context) (output bool) {
	defer func(begin time.Time) {
		log.WithFields(log.Fields{
			"method": "Health",
			"took":   time.Since(begin),
		}).Trace(output)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) CreateDMS(ctx context.Context, input *api.CreateDMSInput) (output *api.CreateDMSOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "CreateDMS"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			var outputCopy api.CreateDMSOutput // Clone output to hide private key
			copier.Copy(&outputCopy, output)
			outputCopy.PrivateKey = "***"
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", outputCopy.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.CreateDMS(ctx, input)
}

func (mw loggingMiddleware) CreateDMSWithCertificateRequest(ctx context.Context, input *api.CreateDMSWithCertificateRequestInput) (output *api.CreateDMSWithCertificateRequestOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "CreateDMSWithCertificateRequest"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.CreateDMSWithCertificateRequest(ctx, input)
}

func (mw loggingMiddleware) UpdateDMSStatus(ctx context.Context, input *api.UpdateDMSStatusInput) (output *api.UpdateDMSStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDMSStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDMSStatus(ctx, input)
}

func (mw loggingMiddleware) UpdateDMSAuthorizedCAs(ctx context.Context, input *api.UpdateDMSAuthorizedCAsInput) (output *api.UpdateDMSAuthorizedCAsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDMSAuthorizedCAs"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDMSAuthorizedCAs(ctx, input)
}

func (mw loggingMiddleware) GetDMSs(ctx context.Context, input *api.GetDMSsInput) (output *api.GetDMSsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDMSs"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDMSs(ctx, input)
}

func (mw loggingMiddleware) GetDMSByName(ctx context.Context, input *api.GetDMSByNameInput) (output *api.GetDMSByNameOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDMSByName"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDMSByName(ctx, input)
}
