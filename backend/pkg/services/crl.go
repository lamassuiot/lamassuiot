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

	goStore "github.com/chartmuseum/storage"
	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

var crlValidate *validator.Validate

type CRLServiceBackend struct {
	caSDK         services.CAService
	logger        *logrus.Entry
	fsStorage     goStore.Backend
	vaRepo        storage.VARepo
	scheduler     *jobs.JobScheduler
	scheduledCRLs map[string]cron.EntryID // Map of CAID to CRL job ID
}

type CRLServiceBuilder struct {
	FsStorage goStore.Backend
	VARepo    storage.VARepo
	Logger    *logrus.Entry
	CAClient  services.CAService
}

func NewCRLService(builder CRLServiceBuilder) services.CRLService {
	crlValidate = validator.New()

	return &CRLServiceBackend{
		caSDK:         builder.CAClient,
		logger:        builder.Logger,
		scheduler:     jobs.NewJobScheduler(false, builder.Logger.WithField("service", "Scheduler")),
		vaRepo:        builder.VARepo,
		fsStorage:     builder.FsStorage,
		scheduledCRLs: map[string]cron.EntryID{},
	}
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

		versionStr = role.CRLOptions.LatestCRLVersion.String()
	}

	crlPem, err := svc.fsStorage.GetObject(fmt.Sprintf("pki/va/crl/%s/%s.crl", input.CAID, versionStr))
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

func (svc CRLServiceBackend) InitCRLRole(ctx context.Context, input services.InitCRLRoleInput) (*models.VARole, error) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	ca, err := svc.caSDK.GetCAByID(ctx, services.GetCAByIDInput{
		CAID: input.CAID,
	})
	if err != nil {
		return nil, err
	}

	role, err := svc.vaRepo.Insert(ctx, &models.VARole{
		CAID: input.CAID,
		CRLOptions: models.VACRLRole{
			Validity:           models.TimeDuration(24 * time.Hour * 7),            // 1 week
			RefreshInterval:    models.TimeDuration(24*time.Hour*6 + 23*time.Hour), // 6 days, 23 hours
			LatestCRLVersion:   models.BigInt{big.NewInt(0)},
			LastCRLTime:        time.Now(),
			KeyIDSinger:        ca.Certificate.KeyID,
			RegenerateOnRevoke: true,
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = svc.CalculateCRL(ctx, services.CalculateCRLInput{
		CAID: input.CAID,
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

	exists, dbRole, err := svc.vaRepo.Get(ctx, input.CAID)
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
	crlVersion.Add(dbRole.CRLOptions.LatestCRLVersion.Int, big.NewInt(1))
	crlDer, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: certList,
		Number:                    crlVersion,
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(dbRole.CRLOptions.Validity)),
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

	// Check if Scheduler already has a job for this CA
	if _, ok := svc.scheduledCRLs[input.CAID]; ok {
		lFunc.Infof("removing previous CRL job for CA %s", input.CAID)
		svc.scheduler.RemoveJob(svc.scheduledCRLs[input.CAID])
	}

	//since itr took time to calculate the CRL, its not possible to calculate the next update time accurately. Can give an aproximation
	lFunc.Infof("scheduling CRL update for CA %s in %s (%s aprox)", input.CAID, dbRole.CRLOptions.RefreshInterval, now.Add(time.Duration(dbRole.CRLOptions.RefreshInterval)))

	scheduleID := svc.scheduler.Schedule(cron.ConstantDelaySchedule{
		Delay: time.Duration(dbRole.CRLOptions.RefreshInterval),
	}, func() {
		_, err := svc.CalculateCRL(ctx, services.CalculateCRLInput{
			CAID: input.CAID,
		})
		if err != nil {
			lFunc.Errorf("something went wrong while calculating CRL: %s", err)
		}
	})

	svc.scheduledCRLs[input.CAID] = scheduleID

	crlPem := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDer})
	err = svc.fsStorage.PutObject(fmt.Sprintf("pki/va/crl/%s/%s.crl", input.CAID, crl.Number), crlPem)
	if err != nil {
		lFunc.Errorf("something went wrong while saving CRL: %s", err)
		return nil, err
	}

	return crl, nil
}
