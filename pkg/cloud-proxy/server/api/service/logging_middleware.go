package service

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
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
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "Health"
		logMsg["took"] = time.Since(begin)

		log.WithFields(logMsg).Trace(output)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMiddleware) GetCloudConnectors(ctx context.Context, input *api.GetCloudConnectorsInput) (output *api.GetCloudConnectorsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCloudConnectors"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCloudConnectors(ctx, input)
}

func (mw loggingMiddleware) GetCloudConnectorByID(ctx context.Context, input *api.GetCloudConnectorByIDInput) (output *api.GetCloudConnectorByIDOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetCloudConnectorByID"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetCloudConnectorByID(ctx, input)
}

func (mw loggingMiddleware) GetDeviceConfiguration(ctx context.Context, input *api.GetDeviceConfigurationInput) (output *api.GetDeviceConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDeviceConfiguration"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDeviceConfiguration(ctx, input)
}

func (mw loggingMiddleware) SynchronizeCA(ctx context.Context, input *api.SynchronizeCAInput) (output *api.SynchronizeCAOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "SynchronizeCA"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.SynchronizeCA(ctx, input)
}

func (mw loggingMiddleware) UpdateCloudProviderConfiguration(ctx context.Context, input *api.UpdateCloudProviderConfigurationInput) (output *api.UpdateCloudProviderConfigurationOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateCloudProviderConfiguration"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateCloudProviderConfiguration(ctx, input)
}

func (mw loggingMiddleware) HandleCreateCAEvent(ctx context.Context, input *api.HandleCreateCAEventInput) (output *api.HandleCreateCAEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "HandleCreateCAEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.HandleCreateCAEvent(ctx, input)
}

func (mw loggingMiddleware) HandleUpdateCAStatusEvent(ctx context.Context, input *api.HandleUpdateCAStatusEventInput) (output *api.HandleUpdateCAStatusEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "HandleUpdateCAStatusEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.HandleUpdateCAStatusEvent(ctx, input)
}

func (mw loggingMiddleware) HandleUpdateCertificateStatusEvent(ctx context.Context, input *api.HandleUpdateCertificateStatusEventInput) (output *api.HandleUpdateCertificateStatusEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "HandleUpdateCertificateStatusEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.HandleUpdateCertificateStatusEvent(ctx, input)
}

func (mw loggingMiddleware) HandleReenrollEvent(ctx context.Context, input *api.HandleReenrollEventInput) (output *api.HandleReenrollEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "HandleReenrollEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.HandleReenrollEvent(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceCertificateStatus(ctx context.Context, input *api.UpdateDeviceCertificateStatusInput) (output *api.UpdateDeviceCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDeviceCertificateStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDeviceCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceDigitalTwinReenrolmentStatus(ctx context.Context, input *api.UpdateDeviceDigitalTwinReenrolmentStatusInput) (output *api.UpdateDeviceDigitalTwinReenrolmentStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDeviceDigitalTwinReenrolmentStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDeviceDigitalTwinReenrolmentStatus(ctx, input)
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

func (mw loggingMiddleware) HandleForceReenrollEvent(ctx context.Context, input *api.HandleForceReenrollEventInput) (output *api.HandleForceReenrollEventOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "HandleForceReenrollEvent"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.HandleForceReenrollEvent(ctx, input)
}
