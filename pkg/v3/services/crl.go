package services

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

type CRLService interface {
	GetCRL(input GetCRLInput) ([]byte, error)
}

type crlServiceImpl struct {
	caSDK  CAService
	logger *logrus.Entry
}

type CRLServiceBuilder struct {
	Logger   *logrus.Entry
	CAClient CAService
}

func NewCRLService(builder CRLServiceBuilder) CRLService {
	return &crlServiceImpl{
		caSDK:  builder.CAClient,
		logger: builder.Logger,
	}
}

type GetCRLInput struct {
	CAID string
}

func (svc crlServiceImpl) GetCRL(input GetCRLInput) ([]byte, error) {
	certList := []pkix.RevokedCertificate{}
	_, err := svc.caSDK.GetCertificatesByCA(GetCertificatesByCAInput{
		CAID: input.CAID,
		ListInput: ListInput[models.Certificate]{
			ExhaustiveRun: true,
			ApplyFunc: func(cert *models.Certificate) {
				certList = append(certList, pkix.RevokedCertificate{
					SerialNumber:   cert.Certificate.SerialNumber,
					RevocationTime: time.Now(),
					Extensions:     []pkix.Extension{},
				})
			},
		},
	})
	if err != nil {
		return nil, err
	}

	ca, err := svc.caSDK.GetCAByID(GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, err
	}

	caSigner := NewCASigner(ca, svc.caSDK)
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)

	now := time.Now()
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificates: certList,
		Number:              big.NewInt(5),
		ThisUpdate:          now,
		NextUpdate:          now.Add(time.Hour * 48),
	}, caCert, caSigner)
	if err != nil {
		return nil, err
	}

	return crl, nil
}
