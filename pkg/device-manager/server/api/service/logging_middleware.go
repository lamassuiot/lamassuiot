package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
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

func (mw loggingMiddleware) GetStats(ctx context.Context, input *api.GetStatsInput) (output *api.GetStatsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetStats"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetStats(ctx, input)
}

func (mw loggingMiddleware) CreateDevice(ctx context.Context, input *api.CreateDeviceInput) (output *api.CreateDeviceOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "CreateDevice"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.CreateDevice(ctx, input)
}

func (mw loggingMiddleware) UpdateDeviceMetadata(ctx context.Context, input *api.UpdateDeviceMetadataInput) (output *api.UpdateDeviceMetadataOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDeviceMetadata"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDeviceMetadata(ctx, input)
}

func (mw loggingMiddleware) DecommisionDevice(ctx context.Context, input *api.DecommisionDeviceInput) (output *api.DecommisionDeviceOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "DecommisionDevice"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.DecommisionDevice(ctx, input)
}

func (mw loggingMiddleware) GetDevices(ctx context.Context, input *api.GetDevicesInput) (output *api.GetDevicesOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDevices"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDevices(ctx, input)
}

func (mw loggingMiddleware) GetDeviceById(ctx context.Context, input *api.GetDeviceByIdInput) (output *api.GetDeviceByIdOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDeviceById"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDeviceById(ctx, input)
}

func (mw loggingMiddleware) IterateDevicesWithPredicate(ctx context.Context, input *api.IterateDevicesWithPredicateInput) (output *api.IterateDevicesWithPredicateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "IterateDevicesWithPredicate"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.IterateDevicesWithPredicate(ctx, input)
}

func (mw loggingMiddleware) AddDeviceSlot(ctx context.Context, input *api.AddDeviceSlotInput) (output *api.AddDeviceSlotOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "AddDeviceSlot"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.AddDeviceSlot(ctx, input)
}

func (mw loggingMiddleware) UpdateActiveCertificateStatus(ctx context.Context, input *api.UpdateActiveCertificateStatusInput) (output *api.UpdateActiveCertificateStatusOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateActiveCertificateStatus"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateActiveCertificateStatus(ctx, input)
}

func (mw loggingMiddleware) RotateActiveCertificate(ctx context.Context, input *api.RotateActiveCertificateInput) (output *api.RotateActiveCertificateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "RotateActiveCertificate"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.RotateActiveCertificate(ctx, input)
}

func (mw loggingMiddleware) RevokeActiveCertificate(ctx context.Context, input *api.RevokeActiveCertificateInput) (output *api.RevokeActiveCertificateOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "RevokeActiveCertificate"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.RevokeActiveCertificate(ctx, input)
}

func (mw loggingMiddleware) GetDeviceLogs(ctx context.Context, input *api.GetDeviceLogsInput) (output *api.GetDeviceLogsOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "GetDeviceLogs"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.GetDeviceLogs(ctx, input)
}

func (mw loggingMiddleware) IsDMSAuthorizedToEnroll(ctx context.Context, input *api.IsDMSAuthorizedToEnrollInput) (output *api.IsDMSAuthorizedToEnrollOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "IsDMSAuthorizedToEnroll"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.IsDMSAuthorizedToEnroll(ctx, input)
}

//--------------------------------------------------------------------------------------------------------------------------

func (mw loggingMiddleware) CACerts(ctx context.Context, aps string) (cas []*x509.Certificate, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "CACerts"
		logMsg["took"] = time.Since(begin)
		logMsg["aps"] = aps

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: number of CAs = %d", len(cas)))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.CACerts(ctx, aps)
}

func (mw loggingMiddleware) Enroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (crt *x509.Certificate, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "Enroll"
		logMsg["took"] = time.Since(begin)
		logMsg["aps"] = aps
		logMsg["csr_cn"] = csr.Subject.CommonName
		logMsg["crt_cn"] = cert.Subject.CommonName

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2)))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.Enroll(ctx, csr, cert, aps)
}

func (mw loggingMiddleware) Reenroll(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate) (crt *x509.Certificate, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "Reenroll"
		logMsg["took"] = time.Since(begin)
		logMsg["csr_cn"] = csr.Subject.CommonName
		logMsg["crt_cn"] = cert.Subject.CommonName

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2)))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.Reenroll(ctx, csr, cert)
}

func (mw loggingMiddleware) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, aps string) (crt *x509.Certificate, key *rsa.PrivateKey, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "ServerKeyGen"
		logMsg["took"] = time.Since(begin)
		logMsg["aps"] = aps
		logMsg["csr_cn"] = csr.Subject.CommonName
		logMsg["crt_cn"] = cert.Subject.CommonName

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2)))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}

func (mw loggingMiddleware) ForceReenroll(ctx context.Context, input *api.ForceReenrollInput) (output *api.ForceReenrollOtput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "ForceReenroll"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.ForceReenroll(ctx, input)
}
