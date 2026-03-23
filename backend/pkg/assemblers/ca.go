package assemblers

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	auditpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	otel "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/otel"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/servicebuilder"
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

// RunCA is the entry point for the standalone CA service binary.
// It loads config, builds the KMS SDK client, assembles the full service, and blocks.
func RunCA(serviceInfo models.APIServiceInfo) {
	servicebuilder.Run[config.CAConfig](serviceInfo, func(conf config.CAConfig, info models.APIServiceInfo) error {
		lKMSClient := helpers.SetupLogger(conf.KMSClient.LogLevel, "CA", "KMS Client")
		kmsHttpCli, err := sdk.BuildHTTPClient(conf.KMSClient.HTTPClient, lKMSClient)
		if err != nil {
			return fmt.Errorf("could not build KMS HTTP client: %s", err)
		}
		kmsSDK := sdk.NewHttpKMSClient(
			sdk.HttpClientWithSourceHeaderInjector(kmsHttpCli, models.CASource),
			fmt.Sprintf("%s://%s:%d%s", conf.KMSClient.Protocol, conf.KMSClient.Hostname, conf.KMSClient.Port, conf.KMSClient.BasePath),
		)
		_, _, _, err = AssembleCAServiceWithHTTPServer(conf, kmsSDK, info)
		return err
	})
}

// AssembleCAService builds and wires the CA service: storage, service, all middlewares, and background jobs.
// The returned scheduler may be nil if certificate monitoring is disabled.
func AssembleCAService(conf config.CAConfig, kmsSDK services.KMSService) (services.CAService, *jobs.JobScheduler, error) {
	sdk.InitOtelSDK(context.Background(), "CA Service", conf.OtelConfig)

	lSvc := helpers.SetupLogger(conf.Logs.Level, "CA", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Event Bus")
	lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Audit Bus")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "CA", "Storage")

	caStorage, certStorage, issuanceStorage, err := createCAStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA storage: %s", err)
	}

	svc, err := lservices.NewCAService(lservices.CAServiceBuilder{
		Logger:                 lSvc,
		KMSService:             kmsSDK,
		CAStorage:              caStorage,
		CertificateStorage:     certStorage,
		IssuanceProfileStorage: issuanceStorage,
		VAServerDomains:        conf.VAServerDomains,
		AllowCascadeDelete:     conf.AllowCascadeDelete,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA service: %s", err)
	}

	backend := svc.(*lservices.CAServiceBackend)
	svc, err = servicebuilder.ApplyMiddlewares(
		"CA", "ca", conf.PublisherEventBus,
		svc, backend.SetService,
		func(s services.CAService) services.CAService { return otel.NewCAOTelTracer()(s) },
		func(s services.CAService, p eventpub.ICloudEventPublisher) services.CAService {
			return eventpub.NewCAEventBusPublisher(p)(s)
		},
		func(s services.CAService, a auditpub.AuditPublisher) services.CAService {
			return auditpub.NewCAAuditEventBusPublisher(a)(s)
		},
		lMessage, lAudit,
	)
	if err != nil {
		return nil, nil, err
	}

	var scheduler *jobs.JobScheduler
	if conf.CertificateMonitoringJob.Enabled {
		lMonitor := helpers.SetupLogger(conf.Logs.Level, "CA", "Crypto Monitoring")
		scheduler = jobs.NewJobScheduler(lMonitor, conf.CertificateMonitoringJob.Frequency, jobs.NewCryptoMonitor(svc, lMonitor))
		scheduler.Start()
	}

	return svc, scheduler, nil
}

// AssembleCAServiceWithHTTPServer assembles the CA service and starts the HTTP server.
// Returns the service, the scheduler (may be nil), the bound port, and any error.
func AssembleCAServiceWithHTTPServer(conf config.CAConfig, kmsSDK services.KMSService, serviceInfo models.APIServiceInfo) (*services.CAService, *jobs.JobScheduler, int, error) {
	svc, scheduler, err := AssembleCAService(conf, kmsSDK)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble CA Service: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "CA", "HTTP Server")
	httpEngine := routes.NewGinEngine(lHttp)
	routes.NewCAHTTPLayer(httpEngine.Group("/"), svc)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not run CA HTTP server: %s", err)
	}

	return &svc, scheduler, port, nil
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
