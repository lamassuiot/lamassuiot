package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	auditpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	commonRoutes "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/eventpublisher"
	log "github.com/sirupsen/logrus"
)

func AssembleCAServiceWithHTTPServer(conf config.CAConfig, serviceInfo models.APIServiceInfo) (*services.CAService, *jobs.JobScheduler, int, error) {
	caService, scheduler, err := AssembleCAService(conf)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble CA Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "CA", "HTTP Server")

	httpEngine := commonRoutes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewCAHTTPLayer(httpGrp, *caService)
	port, err := commonRoutes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not run CA Service http server: %s", err)
	}

	return caService, scheduler, port, nil
}

func AssembleCAService(conf config.CAConfig) (*services.CAService, *jobs.JobScheduler, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "CA", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Event Bus")
	lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Audit Bus")

	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "CA", "Storage")
	lMonitor := helpers.SetupLogger(conf.Logs.Level, "CA", "Crypto Monitoring")

	caStorage, certStorage, caCertRequestStorage, issuerProfilesStorage, err := createCAStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA storage instance: %s", err)
	}

	svc, err := lservices.NewCAService(lservices.CAServiceBuilder{
		Logger:                      lSvc,
		CAStorage:                   caStorage,
		CertificateStorage:          certStorage,
		CACertificateRequestStorage: caCertRequestStorage,
		IssuanceProfileStorage:      issuerProfilesStorage,
		VAServerDomains:             conf.VAServerDomains,
		AllowCascadeDelete:          conf.AllowCascadeDelete,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA service: %v", err)
	}

	caSvc := svc.(*lservices.CAServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "ca", lMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		eventPublisher := &eventpublisher.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "ca",
			Logger:    lMessage,
		}

		auditPublisher := &eventpublisher.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "ca",
			Logger:    lAudit,
		}

		svc = eventpub.NewCAEventBusPublisher(eventPublisher)(svc)
		svc = auditpub.NewCAAuditEventBusPublisher(*eventpublisher.NewAuditPublisher(auditPublisher))(svc)

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

	return &svc, scheduler, nil
}

func createCAStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, storage.CACertificateRequestRepo, storage.IssuanceProfileRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	caStorage, err := engine.GetCAStorage()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not get CA storage: %s", err)
	}

	certStorage, err := engine.GetCertStorage()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not get Cert storage: %s", err)
	}

	issuanceProfileStorage, err := engine.GetIssuanceProfileStorage()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not get Issuance Profile storage: %s", err)
	}

	caCertRequestStorage, err := engine.GetCACertificateRequestStorage()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not get CA Certificate Request storage: %s", err)
	}

	return caStorage, certStorage, caCertRequestStorage, issuanceProfileStorage, nil
}
