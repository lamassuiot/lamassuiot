package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jinzhu/copier"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
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

func (mw loggingMiddleware) UpdateDevManagerAddr(devManagerAddr string) {
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

func (mw loggingMiddleware) UpdateDMS(ctx context.Context, input *api.UpdateDMSInput) (output *api.UpdateDMSOutput, err error) {
	defer func(begin time.Time) {
		var logMsg = map[string]interface{}{}
		logMsg["method"] = "UpdateDMS"
		logMsg["took"] = time.Since(begin)
		logMsg["input"] = input

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", output.ToSerializedLog()))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.UpdateDMS(ctx, input)
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

		fmt.Println("logMsg---")
		fmt.Println(logMsg)
		fmt.Println("err---")
		fmt.Println(err)
		fmt.Println("cert---")
		fmt.Println(cert)
		fmt.Println("crt---")
		fmt.Println(crt)
		if err == nil {
			logMsg["crt_cn"] = cert.Subject.CommonName
			logMsg["crt_sn"] = utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2)
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
		logMsg["crt_sn"] = utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2)

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
		logMsg["crt_sn"] = utils.InsertNth(utils.ToHexInt(cert.SerialNumber), 2)

		if err == nil {
			log.WithFields(logMsg).Trace(fmt.Sprintf("output: %v", utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2)))
		} else {
			log.WithFields(logMsg).Error(err)
		}
	}(time.Now())
	return mw.next.ServerKeyGen(ctx, csr, cert, aps)
}
