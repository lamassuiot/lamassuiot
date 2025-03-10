package services

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type ocspResponder struct {
	caSDK  services.CAService
	logger *logrus.Entry
}

type OCSPServiceBuilder struct {
	Logger   *logrus.Entry
	CAClient services.CAService
}

func NewOCSPService(builder OCSPServiceBuilder) services.OCSPService {
	return &ocspResponder{
		caSDK:  builder.CAClient,
		logger: builder.Logger,
	}
}

func (svc ocspResponder) Verify(ctx context.Context, req *ocsp.Request) ([]byte, error) {
	ocspCrtSN := helpers.SerialNumberToString(req.SerialNumber)
	crt, err := svc.caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: ocspCrtSN,
	})
	if err != nil {
		return nil, err
	}

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{
		SubjectKeyID: crt.IssuerCAMetadata.ID,
	})
	if err != nil {
		return nil, err
	}

	status := ocsp.Unknown
	var revokedAt time.Time
	if crt.Status == models.StatusRevoked {
		status = ocsp.Revoked
		revokedAt = crt.RevocationTimestamp
	} else if crt.Status == models.StatusActive {
		status = ocsp.Good
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      (*x509.Certificate)(ca.Certificate),
		RevocationReason: int(crt.RevocationReason),
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	// make a response to return
	rawResp, err := ocsp.CreateResponse((*x509.Certificate)(ca.Certificate), (*x509.Certificate)(ca.Certificate), rtemplate, NewCASigner(ctx, ca, svc.caSDK))
	if err != nil {
		return nil, err
	}

	// resp, err := ocsp.ParseResponse(rawResp, (*x509.Certificate)(ca.Certificate.Certificate))
	// if err != nil {
	// 	return nil, err
	// }

	return rawResp, nil
}
