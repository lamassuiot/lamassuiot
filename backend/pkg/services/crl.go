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
	service       services.CRLService
}

type CRLServiceBuilder struct {
	FsStorage goStore.Backend
	VARepo    storage.VARepo
	Logger    *logrus.Entry
	CAClient  services.CAService
}

type CRLMiddleware func(services.CRLService) services.CRLService

func NewCRLService(builder CRLServiceBuilder) (services.CRLService, error) {
	crlValidate = validator.New()

	//TODO: Schedule first set of CRL jobs based on existing VARoles
	svc := &CRLServiceBackend{
		caSDK:         builder.CAClient,
		logger:        builder.Logger,
		scheduler:     jobs.NewJobScheduler(true, builder.Logger.WithField("service", "Scheduler")),
		vaRepo:        builder.VARepo,
		fsStorage:     builder.FsStorage,
		scheduledCRLs: map[string]cron.EntryID{},
	}

	svc.service = svc
	svc.scheduler.Start()

	_, err := svc.vaRepo.GetAll(context.Background(), storage.StorageListRequest[models.VARole]{
		ExhaustiveRun: true,
		ApplyFunc: func(v models.VARole) {
			now := time.Now()
			// Check if CRL is still valid
			if v.LatestCRL.ValidUntil.After(now) {
				// Schedule CRL update
				delay := now.Sub(v.LatestCRL.ValidFrom.Add(time.Duration(v.CRLOptions.RefreshInterval)))
				svc.scheduleCRL(context.Background(), v.CAID, delay)
			} else {
				// CRL is not valid anymore, calculate new CRL
				_, err := svc.CalculateCRL(context.Background(), services.CalculateCRLInput{
					CAID: v.CAID,
				})
				if err != nil {
					builder.Logger.Warnf("something went wrong while calculating CRL for CA %s: %s", v.CAID, err)
				}
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("something went wrong while initializing VA service and reading VA roles: %s", err)
	}

	return svc, nil
}

func (svc CRLServiceBackend) SetService(service services.CRLService) {
	svc.service = service
}

func (svc CRLServiceBackend) scheduleCRL(ctx context.Context, caID string, delay time.Duration) {
	lFunc := chelpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Infof("scheduling CRL update for CA %s in %s (%s aprox)", caID, delay, time.Now().Add(delay).Format("2006-01-02T15:04:05Z07:00"))

	scheduleID := svc.scheduler.Schedule(cron.ConstantDelaySchedule{
		Delay: delay,
	}, func() {
		fmt.Println("Calculating CRL")
		_, err := svc.CalculateCRL(context.Background(), services.CalculateCRLInput{
			CAID: caID,
		})
		if err != nil {
			lFunc.Errorf("something went wrong while calculating CRL: %s", err)
		}
	})

	svc.scheduledCRLs[caID] = scheduleID
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
			Validity:           models.TimeDuration(24 * time.Hour * 7), // 1 week
			RefreshInterval:    models.TimeDuration(10 * time.Second),   // 6 days, 23 hours
			KeyIDSinger:        ca.Certificate.KeyID,
			RegenerateOnRevoke: true,
		},
		LatestCRL: models.LatestCRLMeta{
			Version:   models.BigInt{big.NewInt(0)},
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

	// Check if Scheduler already has a job for this CA
	if _, ok := svc.scheduledCRLs[input.CAID]; ok {
		lFunc.Infof("removing previous CRL job for CA %s", input.CAID)
		svc.scheduler.RemoveJob(svc.scheduledCRLs[input.CAID])
	}

	svc.scheduleCRL(ctx, input.CAID, time.Duration(vaRole.CRLOptions.RefreshInterval))

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
