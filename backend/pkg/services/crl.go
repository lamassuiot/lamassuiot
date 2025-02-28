package services

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
)

var crlValidate *validator.Validate

type CRLServiceBackend struct {
	caSDK   services.CAService
	logger  *logrus.Entry
	vaRepo  storage.VARepo
	service services.CRLService
	bucket  *blob.Bucket
}

type CRLServiceBuilder struct {
	VARepo   storage.VARepo
	Logger   *logrus.Entry
	CAClient services.CAService
	Bucket   *blob.Bucket
}

type CRLMiddleware func(services.CRLService) services.CRLService

func NewCRLService(builder CRLServiceBuilder) (services.CRLService, error) {
	crlValidate = validator.New()

	svc := &CRLServiceBackend{
		caSDK:  builder.CAClient,
		logger: builder.Logger,
		vaRepo: builder.VARepo,
	}

	svc.service = svc

	return svc, nil
}

func (svc CRLServiceBackend) SetService(service services.CRLService) {
	svc.service = service
}

func (svc CRLServiceBackend) GetCRL(ctx context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	versionStr := input.CRLVersion.String()
	if input.CRLVersion.Cmp(big.NewInt(0)) == 0 {
		exists, role, err := svc.vaRepo.Get(ctx, input.CAID)
		if err != nil {
			lFunc.Errorf("something went wrong while reading VA role: %s", err)
			return nil, err
		}

		if !exists {
			lFunc.Errorf("VA role for CA %s does not exist", input.CAID)
			return nil, fmt.Errorf("VA role for CA %s does not exist", input.CAID)
		}

		versionStr = role.LatestCRL.Version.String()
	}

	crlPem, err := svc.bucket.ReadAll(ctx, fmt.Sprintf("pki/va/crl/%s/%s.crl", input.CAID, versionStr))
	if err != nil {
		lFunc.Errorf("something went wrong while reading CRL: %s", err)
		return nil, err
	}

	crlDer, _ := pem.Decode(crlPem.Content)

	crl, err := x509.ParseRevocationList(crlDer.Bytes)
	if err != nil {
		lFunc.Errorf("something went wrong while parsing CRL: %s", err)
		return nil, err
	}

	return crl, nil
}

func (svc CRLServiceBackend) InitCRLRole(ctx context.Context, caID string) (*models.VARole, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: caID,
	})
	if err != nil {
		return nil, err
	}

	role, err := svc.vaRepo.Insert(ctx, &models.VARole{
		CAID: caID,
		CRLOptions: models.VACRLRole{
			Validity:           models.TimeDuration(24 * time.Hour * 7),            // 1 week
			RefreshInterval:    models.TimeDuration(24*time.Hour*6 + 23*time.Hour), // 6 days, 23 hours
			KeyIDSigner:        ca.Certificate.KeyID,
			RegenerateOnRevoke: true,
		},
		LatestCRL: models.LatestCRLMeta{
			Version:   models.BigInt{Int: big.NewInt(0)},
			ValidFrom: time.Now(),
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = svc.CalculateCRL(ctx, services.CalculateCRLInput{
		CAID: caID,
	})
	if err != nil {
		lFunc.Errorf("something went wrong while calculating first CRL: %s", err)
		return nil, err
	}

	return role, nil
}

func (svc CRLServiceBackend) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (*x509.RevocationList, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	err := crlValidate.Struct(input)
	if err != nil {
		lFunc.Errorf("struct validation error: %s", err)
		return nil, errs.ErrValidateBadRequest
	}

	exists, vaRole, err := svc.vaRepo.Get(ctx, input.CAID)
	if err != nil {
		lFunc.Errorf("something went wrong while reading VA role: %s", err)
		return nil, err
	}

	if !exists {
		lFunc.Errorf("VA role for CA %s does not exist", input.CAID)
		return nil, fmt.Errorf("VA role for CA %s does not exist", input.CAID)
	}

	certList := []x509.RevocationListEntry{}
	lFunc.Debugf("reading CA %s certificates", input.CAID)
	_, err = svc.caSDK.GetCertificatesByCaAndStatus(ctx, services.GetCertificatesByCaAndStatusInput{
		CAID:   input.CAID,
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
		lFunc.Errorf("something went wrong while reading CA %s certificates: %s", input.CAID, err)
		return nil, err
	}

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput(input))
	if err != nil {
		return nil, err
	}

	caSigner := NewCASigner(ctx, ca, svc.caSDK)
	caCert := (*x509.Certificate)(ca.Certificate.Certificate)

	lFunc.Debugf("creating revocation list. CA %s", input.CAID)
	now := time.Now()

	crlVersion := big.NewInt(0)
	crlVersion.Add(vaRole.LatestCRL.Version.Int, big.NewInt(1))
	crlDer, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: certList,
		Number:                    crlVersion,
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(vaRole.CRLOptions.Validity)),
	}, caCert, caSigner)
	if err != nil {
		lFunc.Errorf("something went wrong while creating revocation list: %s", err)
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		lFunc.Errorf("something went wrong while parsing revocation list: %s", err)
		return nil, err
	}

	crlPem := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDer})
	err = svc.fsStorage.PutObject(fmt.Sprintf("pki/va/crl/%s/%s.crl", input.CAID, crl.Number), crlPem)
	if err != nil {
		lFunc.Errorf("something went wrong while saving CRL: %s", err)
		return nil, err
	}

	vaRole.LatestCRL = models.LatestCRLMeta{
		Version:    models.BigInt{crl.Number},
		ValidFrom:  crl.ThisUpdate,
		ValidUntil: crl.NextUpdate,
	}

	_, err = svc.vaRepo.Update(ctx, vaRole)
	if err != nil {
		lFunc.Errorf("something went wrong while updating VA role: %s", err)
		return nil, err
	}

	return crl, nil
}

func (svc CRLServiceBackend) GetVARole(ctx context.Context, input services.GetVARoleInput) (*models.VARole, error) {
	exists, role, err := svc.vaRepo.Get(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("VA role for CA %s does not exist", input.CAID)
	}

	return role, nil
}

func (svc CRLServiceBackend) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	return svc.vaRepo.GetAll(ctx, storage.StorageListRequest[models.VARole]{
		ExhaustiveRun: input.ExhaustiveRun,
		QueryParams:   input.QueryParameters,
		ExtraOpts:     map[string]interface{}{},
		ApplyFunc: func(role models.VARole) {
			input.ApplyFunc(role)
		},
	})
}

func (svc CRLServiceBackend) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (*models.VARole, error) {
	exists, role, err := svc.vaRepo.Get(ctx, input.CAID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("VA role for CA %s does not exist", input.CAID)
	}

	role.CRLOptions = input.CRLRole

	return svc.vaRepo.Update(ctx, role)
}
