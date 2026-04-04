package assemblers

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	bhelpers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	auditpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	otel "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/otel"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	sdk "github.com/lamassuiot/lamassuiot/sdk/v3"
	log "github.com/sirupsen/logrus"
)

func AssembleCAServiceWithHTTPServer(conf config.CAConfig, kmsSDK services.KMSService, serviceInfo models.APIServiceInfo) (*services.CAService, *jobs.JobScheduler, int, error) {
	caService, scheduler, err := AssembleCAService(conf, kmsSDK)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble CA Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "CA", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewCAHTTPLayer(httpGrp, *caService)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not run CA Service http server: %s", err)
	}

	return caService, scheduler, port, nil
}

func AssembleCAService(conf config.CAConfig, kmsSDK services.KMSService) (*services.CAService, *jobs.JobScheduler, error) {
	sdk.InitOtelSDK(context.Background(), "CA Service", conf.OtelConfig)

	lSvc := helpers.SetupLogger(conf.Logs.Level, "CA", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Event Bus")
	lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Audit Bus")

	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "CA", "Storage")
	lMonitor := helpers.SetupLogger(conf.Logs.Level, "CA", "Crypto Monitoring")

	lKMSKeys := helpers.SetupLogger(conf.Logs.Level, "CA", "KMS Keys creation")

	caStorage, certStorage, issuerProfilesStorage, err := createCAStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA storage instance: %s", err)
	}

	svc, err := lservices.NewCAService(lservices.CAServiceBuilder{
		Logger:                 lSvc,
		KMSService:             kmsSDK,
		CAStorage:              caStorage,
		CertificateStorage:     certStorage,
		IssuanceProfileStorage: issuerProfilesStorage,
		VAServerDomains:        conf.VAServerDomains,
		AllowCascadeDelete:     conf.AllowCascadeDelete,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA service: %v", err)
	}

	caSvc := svc.(*lservices.CAServiceBackend)

	// Add OTel middleware
	svc = otel.NewCAOTelTracer()(svc)
	caSvc.SetService(svc)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "ca", lMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		eventPublisher := &eventpub.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "ca",
			Logger:    lMessage,
		}

		auditPublisher := &eventpub.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "ca",
			Logger:    lAudit,
		}

		svc = eventpub.NewCAEventBusPublisher(eventPublisher)(svc)
		svc = auditpub.NewCAAuditEventBusPublisher(*auditpub.NewAuditPublisher(auditPublisher))(svc)

		//this utilizes the middlewares from within the CA service (if svc.service.func is used instead of regular svc.func)
		caSvc.SetService(svc)
	}

	var scheduler *jobs.JobScheduler
	if conf.CertificateMonitoringJob.Enabled {
		log.Infof("Crypto Monitoring is enabled")
		monitorJob := jobs.NewCryptoMonitor(svc, lMonitor)
		scheduler = jobs.NewJobScheduler(lMonitor, conf.CertificateMonitoringJob.Frequency, monitorJob)
		scheduler.Start()
	}

	if conf.RegisterKeysInKMS {
		log.Infof("Register Keys in KMS is enabled")
		err := registerCAKeysInKMS(lKMSKeys, caStorage, kmsSDK)
		if err != nil {
			return nil, nil, fmt.Errorf("could not register CA keys in KMS: %s", err)
		}
	}

	return &svc, scheduler, nil
}

func createCAStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, storage.IssuanceProfileRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	caStorage, err := engine.GetCAStorage()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get CA storage: %s", err)
	}

	certStorage, err := engine.GetCertStorage()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get Cert storage: %s", err)
	}

	issuanceProfileStorage, err := engine.GetIssuanceProfileStorage()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get Issuance Profile storage: %s", err)
	}

	return caStorage, certStorage, issuanceProfileStorage, nil
}

func registerCAKeysInKMS(logger *log.Entry, caStorage storage.CACertificatesRepo, kmsSDK services.KMSService) error {
	ctx := context.Background()

	err := waitForKMSService(ctx, logger, kmsSDK)
	if err != nil {
		return fmt.Errorf("could not connect to KMS service: %s", err)
	}

	_, err = caStorage.SelectAll(ctx, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: true,
		ApplyFunc: func(ca models.CACertificate) {
			keyID := ca.Certificate.SubjectKeyID
			name := fmt.Sprintf("Key For CA CN=%s", ca.Certificate.Subject.CommonName)

			// Check if key already exists in KMS
			_, err := kmsSDK.GetKey(ctx, services.GetKeyInput{
				Identifier: keyID,
			})
			if err == nil {
				logger.Infof("Key with ID %s already exists in KMS. Skipping registration.", keyID)
				return
			}

			_, err = kmsSDK.RegisterExistingKey(ctx, services.RegisterExistingKeyInput{
				KeyID: keyID,
				Name:  name,
			})

			if err != nil {
				logger.Errorf("failed to register key %s for CA %s: %s", keyID, name, err)
				return
			}
			logger.Infof("successfully registered key %s for CA %s in KMS", keyID, name)

			_, err = kmsSDK.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
				ID: keyID,
				Patches: helpers.NewPatchBuilder().Add(helpers.JSONPointerBuilder(models.KMSBindResourceKey, "-"), models.KMSBindResource{
					ResourceType: "certificate",
					ResourceID:   bhelpers.SerialNumberToHexString(ca.Certificate.Certificate.SerialNumber),
				}).Build(),
			})
			if err != nil {
				logger.Errorf("could not bind CA %s to key %s in KMS: %s", ca.Certificate.Subject.CommonName, keyID, err)
				return
			}
			logger.Infof("successfully binded CA %s to key %s in KMS", ca.Certificate.Subject.CommonName, keyID)
		},
	})
	return nil
}

func waitForKMSService(ctx context.Context, logger *log.Entry, kmsSDK services.KMSService) error {
	var err error
	for attempt := 1; attempt <= 10; attempt++ {
		logger.Infof("attempting to connect to KMS service (attempt %d/%d)", attempt, 10)

		_, err = kmsSDK.GetCryptoEngineProvider(ctx)
		if err != nil {
			logger.Warnf("KMS service is not available yet. Retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
			continue
		}

		logger.Info("successfully connected to KMS service")
		err = nil
		break
	}
	return err
}
