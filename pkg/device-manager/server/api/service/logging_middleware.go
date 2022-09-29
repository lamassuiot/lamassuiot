package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
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

func (mw loggingMiddleware) GetStats(ctx context.Context, input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetStats")
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
	return mw.next.GetStats(ctx, input)
}

func (mw loggingMiddleware) CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (output *api.CreateDeviceOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "CreateDevice")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "device_id", output.ID)
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.CreateDevice(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (output *api.UpdateDeviceMetadataOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateDeviceMetadata")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "device_id", output.ID)
				logMsg = append(logMsg, "status", output.Status)
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.UpdateDeviceMetadata(ctx, input)
}

func (mw loggingMiddleware) DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (output *api.DecommisionDeviceOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "DecommisionDevice")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "device_id", output.ID)
				logMsg = append(logMsg, "status", output.Status)
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.DecommisionDevice(ctx, input)
}

func (mw loggingMiddleware) GetDevices(ctx context.Context, input *api.GetDevicesInput) (output *api.GetDevicesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetDevices")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			if output != nil {
				logMsg = append(logMsg, "total_devices", output.TotalDevices)
			}
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.GetDevices(ctx, input)
}

func (mw loggingMiddleware) GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (output *api.GetDeviceByIdOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetDeviceById")
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
	return mw.next.GetDeviceById(ctx, input)
}

func (mw loggingMiddleware) IterateDevicesWithPredicate(ctx context.Context, input *api.IterateDevicesWithPredicateInput) (output *api.IterateDevicesWithPredicateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "IterateDevicesWithPredicate")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.IterateDevicesWithPredicate(ctx, input)
}

func (mw loggingMiddleware) AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (output *api.AddDeviceSlotOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "AddDeviceSlot")
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
	return mw.next.AddDeviceSlot(ctx, input)
}

func (mw loggingMiddleware) UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (output *api.UpdateActiveCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "UpdateActiveCertificateStatus")
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
	return mw.next.UpdateActiveCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (output *api.RotateActiveCertificateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "RotateActiveCertificate")
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
	return mw.next.RotateActiveCertificate(ctx, input)
}

func (mw loggingMiddleware) RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (output *api.RevokeActiveCertificateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "RevokeActiveCertificate")
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
	return mw.next.RevokeActiveCertificate(ctx, input)
}

func (mw loggingMiddleware) GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (output *api.GetDeviceLogsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetDeviceLogs")
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
	return mw.next.GetDeviceLogs(ctx, input)
}

func (mw loggingMiddleware) IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (output *api.IsDMSAuthorizedToEnrollOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "IsDMSAuthorizedToEnroll")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "input", input)
		if err == nil {
			logMsg = append(logMsg, "output", output)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.IsDMSAuthorizedToEnroll(ctx, input)
}

//--------------------------------------------------------------------------------------------------------------------------

func (mw loggingMiddleware) CACerts(ctx context.Context, aps string) (cas []*x509.Certificate, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "CACerts")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "aps", aps)
		if err == nil {
			logMsg = append(logMsg, "cas", cas)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.CACerts(ctx, aps)
}

func (mw loggingMiddleware) Enroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (crt *x509.Certificate, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "Enroll")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "csr", csr)
		logMsg = append(logMsg, "cert", cert)
		logMsg = append(logMsg, "aps", aps)
		if err == nil {
			logMsg = append(logMsg, "crt", crt)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.Enroll(ctx, csr, cert, aps)
}

func (mw loggingMiddleware) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate) (crt *x509.Certificate, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "Reenroll")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "csr", csr)
		logMsg = append(logMsg, "cert", cert)
		if err == nil {
			logMsg = append(logMsg, "crt", crt)
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.Reenroll(ctx, csr, cert)
}

func (mw loggingMiddleware) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (crt *x509.Certificate, key *rsa.PrivateKey, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "GetCloudConnectors")
		logMsg = append(logMsg, "took", time.Since(begin))
		logMsg = append(logMsg, "csr", csr)
		logMsg = append(logMsg, "cert", cert)
		logMsg = append(logMsg, "aps", aps)
		if err == nil {
			logMsg = append(logMsg, "crt", crt)
			logMsg = append(logMsg, "key", "*****")
		} else {
			logMsg = append(logMsg, "err", err)
		}
		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}

func (mw loggingMiddleware) ForceReenroll(ctx context.Context, input *api.ForceReenrollInput) (output *api.ForceReenrollOtput, err error) {
	defer func(begin time.Time) {
		var logMsg = []interface{}{}
		logMsg = append(logMsg, "method", "ForceReenroll")
		logMsg = append(logMsg, "took", time.Since(begin))

		logMsg = append(logMsg, "err", err)

		mw.logger.Log(logMsg...)
	}(time.Now())
	return mw.next.ForceReenroll(ctx, input)
}
