package services

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type OCSPService interface {
	Verify(ctx context.Context, req *ocsp.Request) ([]byte, error)
}

type ocspResponder struct {
	caSDK  CAService
	logger *logrus.Entry
}

type OCSPServiceBuilder struct {
	Logger   *logrus.Entry
	CAClient CAService
}

func NewOCSPService(builder OCSPServiceBuilder) OCSPService {
	return &ocspResponder{
		caSDK:  builder.CAClient,
		logger: builder.Logger,
	}
}

func (svc ocspResponder) Verify(ctx context.Context, req *ocsp.Request) ([]byte, error) {
	ocspCrtSN := helpers.SerialNumberToString(req.SerialNumber)
	crt, err := svc.caSDK.GetCertificateBySerialNumber(ctx, GetCertificatesBySerialNumberInput{
		SerialNumber: ocspCrtSN,
	})
	if err != nil {
		return nil, err
	}

	ca, err := svc.caSDK.GetCAByID(ctx, GetCAByIDInput{
		CAID: crt.IssuerCAMetadata.ID,
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
		Certificate:      (*x509.Certificate)(ca.Certificate.Certificate),
		RevocationReason: int(crt.RevocationReason),
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	// make a response to return
	rawResp, err := ocsp.CreateResponse((*x509.Certificate)(ca.Certificate.Certificate), (*x509.Certificate)(ca.Certificate.Certificate), rtemplate, NewCASigner(ctx, ca, svc.caSDK))
	if err != nil {
		return nil, err
	}

	// resp, err := ocsp.ParseResponse(rawResp, (*x509.Certificate)(ca.Certificate.Certificate))
	// if err != nil {
	// 	return nil, err
	// }

	return rawResp, nil
}
