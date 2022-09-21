package service

import (
	"context"
	"time"

	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
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

func (mw loggingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) GetCloudConnectors(ctx context.Context, input *api.GetCloudConnectorsInput) (output *api.GetCloudConnectorsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCloudConnectors")
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
	return mw.next.GetCloudConnectors(ctx, input)
}

func (mw loggingMiddleware) GetCloudConnectorByID(ctx context.Context, input *api.GetCloudConnectorByIDInput) (output *api.GetCloudConnectorByIDOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCloudConnectorByID")
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
	return mw.next.GetCloudConnectorByID(ctx, input)
}

func (mw loggingMiddleware) GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (output *api.GetDeviceConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetDeviceConfiguration")
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
	return mw.next.GetDeviceConfiguration(ctx, input)
}

func (mw loggingMiddleware) SynchronizeCA(ctx context.Context, input *api.SynchronizeCAInput) (output *api.SynchronizeCAOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "SynchronizeCA")
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
	return mw.next.SynchronizeCA(ctx, input)
}

func (mw loggingMiddleware) UpdateCloudProviderConfiguration(ctx context.Context, input *api.UpdateCloudProviderConfigurationInput) (output *api.UpdateCloudProviderConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateCloudProviderConfiguration")
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
	return mw.next.UpdateCloudProviderConfiguration(ctx, input)
}

func (mw loggingMiddleware) HandleCreateCAEvent(ctx context.Context, input *api.HandleCreateCAEventInput) (output *api.HandleCreateCAEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "HandleCreateCAEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.HandleCreateCAEvent(ctx, input)
}

func (mw loggingMiddleware) HandleUpdateCAStatusEvent(ctx context.Context, input *api.HandleUpdateCAStatusEventInput) (output *api.HandleUpdateCAStatusEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "HandleUpdateCAStatusEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.HandleUpdateCAStatusEvent(ctx, input)
}

func (mw loggingMiddleware) HandleUpdateCertificateStatusEvent(ctx context.Context, input *api.HandleUpdateCertificateStatusEventInput) (output *api.HandleUpdateCertificateStatusEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "HandleUpdateCertificateStatusEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.HandleUpdateCertificateStatusEvent(ctx, input)
}

func (mw loggingMiddleware) HandleReenrollEvent(ctx context.Context, input *api.HandleReenrollEventInput) (output *api.HandleReenrollEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "HandleReenrollEvent")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.HandleReenrollEvent(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (output *api.UpdateDeviceCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateDeviceCertificateStatus")
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
	return mw.next.UpdateDeviceCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceDigitalTwinReenrolmentStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrolmentStatusInput) (output *api.UpdateDeviceDigitalTwinReenrolmentStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateDeviceDigitalTwinReenrolmentStatus")
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
	return mw.next.UpdateDeviceDigitalTwinReenrolmentStatus(ctx, input)
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
