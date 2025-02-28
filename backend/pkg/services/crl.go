package services

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

var crlValidate *validator.Validate

type crlServiceImpl struct {
	caSDK     services.CAService
	kmsSDK    services.AsymmetricKMSService
	logger    *logrus.Entry
	vaDomains []string
}

type CRLServiceBuilder struct {
	Logger    *logrus.Entry
	CAClient  services.CAService
	KMSSDK    services.AsymmetricKMSService
	VADomains []string
}

func NewCRLService(builder CRLServiceBuilder) services.CRLService {
	crlValidate = validator.New()
	return &crlServiceImpl{
		caSDK:     builder.CAClient,
		logger:    builder.Logger,
		vaDomains: builder.VADomains,
	}
}

func (svc crlServiceImpl) GetCRL(ctx context.Context, input services.GetCRLInput) ([]byte, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	var crlCA *models.CACertificate
	_, err = svc.caSDK.GetCAs(ctx, services.GetCAsInput{
		QueryParameters: &resources.QueryParameters{
			Filters: []resources.FilterOption{
				{
					Field:           "key_id", // since KeyID is used as the AKI, it should be used as the filter field
					Value:           input.AuthorityKeyId,
					FilterOperation: resources.StringEqual,
				},
			},
			PageSize: 1,
		},
		ApplyFunc: func(ca models.CACertificate) {
			crlCA = &ca
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading CA %s: %s", input.AuthorityKeyId, err)
		return nil, err
	}

	if crlCA == nil {
		lFunc.Errorf("CA %s not found", input.AuthorityKeyId)
		return nil, fmt.Errorf("CA %s not found", input.AuthorityKeyId)
	}

	certList := []x509.RevocationListEntry{}
	lFunc.Debugf("reading CA %s certificates", crlCA.ID)
	_, err = svc.caSDK.GetCertificatesByCaAndStatus(ctx, services.GetCertificatesByCaAndStatusInput{
		CAID:   crlCA.ID,
		Status: models.StatusRevoked,
		ListInput: resources.ListInput[models.Certificate]{
			ExhaustiveRun: true,
			QueryParameters: &resources.QueryParameters{
				PageSize: 15,
			},
			ApplyFunc: func(cert models.Certificate) {
				certList = append(certList, x509.RevocationListEntry{
					SerialNumber:   cert.Certificate.SerialNumber,
					RevocationTime: time.Now(),
					Extensions:     []pkix.Extension{},
					ReasonCode:     int(cert.RevocationReason),
				})
			},
		},
	})
	if err != nil {
		lFunc.Errorf("something went wrong while reading CA %s certificates: %s", crlCA.ID, err)
		return nil, err
	}

	caSigner := NewKeyPairCryptoSigner(ctx, crlCA, svc.caSDK)
	caCert := (*x509.Certificate)(crlCA.Certificate.Certificate)

	extensions := []pkix.Extension{}

	idp, err := svc.getDistributionPointExtension(crlCA.Certificate.KeyID)
	if err != nil {
		lFunc.Errorf("something went wrong while creating Issuing Distribution Point extension: %s", err)
		return nil, err
	}

	extensions = append(extensions, *idp)

	lFunc.Debugf("creating revocation list. CA %s", crlCA.ID)
	now := time.Now()
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: certList,
		Number:                    big.NewInt(time.Now().UnixMilli()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Hour * 48),
		ExtraExtensions:           extensions,
	}, caCert, caSigner)
	if err != nil {
		lFunc.Errorf("something went wrong while creating revocation list: %s", err)
		return nil, err
	}

	return crl, nil
}

func (svc crlServiceImpl) getDistributionPointExtension(aki string) (*pkix.Extension, error) {
	type DistributionPointName struct { // CHOICE
		FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
		RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
	}

	// RFC 5280. Section 5.2.5,
	type IssuingDistributionPoint struct {
		DistributionPoint          DistributionPointName `asn1:"tag:0,optional"`
		OnlyContainsUserCerts      bool                  `asn1:"tag:1"`
		OnlyContainsCACerts        bool                  `asn1:"tag:2"`
		OnlySomeReasons            asn1.BitString        `asn1:"tag:3,optional"`
		IndirectCRL                bool                  `asn1:"tag:4"`
		OnlyContainsAttributeCerts bool                  `asn1:"tag:5"`
	}

	idpNames := []asn1.RawValue{}
	for _, name := range svc.vaDomains {
		idpNames = append(idpNames, asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(fmt.Sprintf("http://%s/crl/%s", name, aki))})
	}

	// Add Issuing Distribution Point
	idp, err := asn1.Marshal(IssuingDistributionPoint{
		DistributionPoint: DistributionPointName{
			FullName: idpNames,
		},
	})
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       []int{2, 5, 29, 28},
		Critical: true,
		Value:    idp,
	}, nil
}
