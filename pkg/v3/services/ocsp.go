package services

import (
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type OCSPService interface {
	Verify(req *ocsp.Request) (*ocsp.Response, error)
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

func (svc ocspResponder) Verify(req *ocsp.Request) (*ocsp.Response, error) {
	ocspCrtSN := helpers.SerialNumberToString(req.SerialNumber)
	crt, err := svc.caSDK.GetCertificateBySerialNumber(GetCertificatesBySerialNumberInput{
		SerialNumber: ocspCrtSN,
	})
	if err != nil {
		return nil, err
	}

	ca, err := svc.caSDK.GetCAByID(GetCAByIDInput{
		CAID: crt.IssuerCAMetadata.CAID,
	})
	if err != nil {
		return nil, err
	}

	status := ocsp.Unknown
	var revokedAt time.Time
	if err == nil {
		if crt.Status == models.StatusRevoked {
			status = ocsp.Revoked
			revokedAt = crt.RevocationTimestamp
		} else if crt.Status == models.StatusActive {
			status = ocsp.Good
		}
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      (*x509.Certificate)(ca.Certificate.Certificate),
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	// make a response to return
	rawResp, err := ocsp.CreateResponse((*x509.Certificate)(ca.Certificate.Certificate), (*x509.Certificate)(ca.Certificate.Certificate), rtemplate, NewCASigner(ca, svc.caSDK))
	if err != nil {
		return nil, err
	}

	resp, err := ocsp.ParseResponse(rawResp, (*x509.Certificate)(ca.Certificate.Certificate))
	if err != nil {
		return nil, err
	}

	return resp, nil
}
