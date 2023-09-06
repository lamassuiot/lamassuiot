package service

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-provider/common/api"
	log "github.com/sirupsen/logrus"
)

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

func (mw loggingMiddleware) RegisterCA(ctx context.Context, input *api.RegisterCAInput) (output *api.RegisterCAOutput, err error) {
	defer func(begin time.Time) {
		log.WithFields(log.Fields{
			"method": "RegisterCA",
			"output": output,
			"took":   time.Since(begin),
		}).Trace(fmt.Sprintf("output: %v", output))
	}(time.Now())
	return mw.next.RegisterCA(ctx, input)
}

func (mw loggingMiddleware) UpdateConfiguration(ctx context.Context, input *api.UpdateConfigurationInput) (output *api.UpdateConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateConfiguration"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.Serialize()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateConfiguration(ctx, input)
}

func (mw loggingMiddleware) GetConfiguration(ctx context.Context, input *api.GetConfigurationInput) (output *api.GetConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetConfiguration"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.Serialize()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetConfiguration(ctx, input)
}

func (mw loggingMiddleware) GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (output *api.GetDeviceConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDeviceConfiguration"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.Serialize()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDeviceConfiguration(ctx, input)
}

func (mw loggingMiddleware) UpdateCAStatus(ctx context.Context, input *api.UpdateCAStatusInput) (output *api.UpdateCAStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateCAStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.Serialize()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateCAStatus(ctx, input)
}

func (mw loggingMiddleware) UpdateDMSCaCerts(ctx context.Context, input *api.UpdateDMSCaCertsInput) (output *api.UpdateDMSCaCertsOutput, err error) {
	defer func(begin time.Time) {
		log.WithFields(log.Fields{
			"method": "UpdateDMSCaCerts",
			"output": output,
			"took":   time.Since(begin),
		}).Trace(fmt.Sprintf("output: %v", output))
	}(time.Now())
	return mw.next.UpdateDMSCaCerts(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (output *api.UpdateDeviceCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDeviceCertificateStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.Serialize()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDeviceCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceDigitalTwinReenrollmentStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrollmentStatusInput) (output *api.UpdateDeviceDigitalTwinReenrollmentStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDeviceDigitalTwinReenrollmentStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.Serialize()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDeviceDigitalTwinReenrollmentStatus(ctx, input)
}
