package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type ocspResponder struct {
	caSDK      services.CAService
	kmsService services.KMSService
	logger     *logrus.Entry
}

type OCSPServiceBuilder struct {
	Logger    *logrus.Entry
	CAClient  services.CAService
	KMSClient services.KMSService
}

func NewOCSPService(builder OCSPServiceBuilder) services.OCSPService {
	return &ocspResponder{
		caSDK:      builder.CAClient,
		kmsService: builder.KMSClient,
		logger:     builder.Logger,
	}
}

func ocspIssuerMatches(request *ocsp.Request, issuer *x509.Certificate) bool {
	if request == nil || issuer == nil {
		return false
	}
	requestDER, err := ocsp.CreateRequest(issuer, issuer, &ocsp.RequestOptions{Hash: request.HashAlgorithm})
	if err != nil {
		return false
	}
	expected, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return false
	}
	return request.HashAlgorithm == expected.HashAlgorithm &&
		bytes.Equal(request.IssuerNameHash, expected.IssuerNameHash) &&
		bytes.Equal(request.IssuerKeyHash, expected.IssuerKeyHash)
}

func (svc ocspResponder) Verify(ctx context.Context, req *ocsp.Request) ([]byte, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("OCSP request is required")
	}

	ocspCrtSN := helpers.SerialNumberToHexString(req.SerialNumber)
	crt, err := svc.caSDK.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: ocspCrtSN,
	})
	if err != nil {
		return nil, err
	}
	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: crt.IssuerCAMetadata.ID,
	})
	if err != nil {
		return nil, err
	}
	if crt.TenantID != tenantContext.TenantID || ca.TenantID != tenantContext.TenantID ||
		!ocspIssuerMatches(req, (*x509.Certificate)(ca.Certificate.Certificate)) {
		return nil, errs.ErrCANotFound
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
	rawResp, err := ocsp.CreateResponse((*x509.Certificate)(ca.Certificate.Certificate), (*x509.Certificate)(ca.Certificate.Certificate), rtemplate, NewCertificateSigner(ctx, &ca.Certificate, svc.kmsService))
	if err != nil {
		return nil, err
	}

	// resp, err := ocsp.ParseResponse(rawResp, (*x509.Certificate)(ca.Certificate.Certificate))
	// if err != nil {
	// 	return nil, err
	// }

	return rawResp, nil
}
