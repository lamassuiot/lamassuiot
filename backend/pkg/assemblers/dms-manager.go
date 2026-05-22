package assemblers

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	sdk "github.com/lamassuiot/lamassuiot/sdk/v3"
	log "github.com/sirupsen/logrus"
)

func AssembleDMSManagerServiceWithHTTPServer(conf config.DMSconfig, kmsService services.KMSService, caService services.CAService, deviceService services.DeviceManagerService, serviceInfo models.APIServiceInfo) (*services.DMSManagerService, int, error) {
	service, err := AssembleDMSManagerService(conf, kmsService, caService, deviceService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble DMS Manager Service. Exiting: %s", err)
	}

	lHttp := chelpers.SetupLogger(conf.Server.LogLevel, "DMS Manager", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewDMSManagerHTTPLayer(lHttp, httpGrp, *service)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run DMS Manager http server: %s", err)
	}

	return service, port, nil
}

func AssembleDMSManagerService(conf config.DMSconfig, kmsService services.KMSService, caService services.CAService, deviceService services.DeviceManagerService) (*services.DMSManagerService, error) {
	sdk.InitOtelSDK(context.Background(), "DMS Manager Service", conf.OtelConfig)

	lSvc := chelpers.SetupLogger(conf.Logs.Level, "DMS Manager", "Service")
	lMessaging := chelpers.SetupLogger(conf.PublisherEventBus.LogLevel, "DMS Manager", "Event Bus")
	lStorage := chelpers.SetupLogger(conf.Storage.LogLevel, "DMS Manager", "Storage")

	downCert, err := chelpers.ReadCertificateFromFile(conf.DownstreamCertificateFile)
	if err != nil {
		return nil, fmt.Errorf("could not read downstream certificate: %s", err)
	}

	devStorage, err := createDMSStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create dms storage instance: %s", err)
	}

	cmptxStorage, err := createCMPTransactionStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create CMP transaction storage instance: %s", err)
	}

	// Background janitor: delete expired CMP transactions periodically.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			if dErr := cmptxStorage.DeleteExpired(context.Background()); dErr != nil {
				lStorage.Warnf("CMP tx DeleteExpired: %v", dErr)
			}
		}
	}()

	var cmpReporter cmpwfx.CMPReporter
	if conf.WFX.Enabled {
		lWFX := chelpers.SetupLogger(conf.WFX.LogLevel, "DMS Manager", "WFX")
		cmpReporter, err = cmpwfx.NewCMPReporter(conf.WFX, lWFX)
		if err != nil {
			return nil, fmt.Errorf("could not create CMP WFX reporter: %s", err)
		}
	}

	svc := lservices.NewDMSManagerService(lservices.DMSManagerBuilder{
		Logger:                lSvc,
		DMSStorage:            devStorage,
		CMPTransactionStorage: cmptxStorage,
		CMPWFXReporter:        cmpReporter,
		KMSClient:             kmsService,
		CAClient:              caService,
		DevManagerCli:         deviceService,
		DownstreamCertificate: downCert,
	})

	dmsSvc := svc.(*lservices.DMSManagerServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "dms-manager", lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		svc = eventpub.NewDMSEventPublisher(&eventpub.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "dms-manager",
			Logger:    lMessaging,
		})(svc)

		//this utilizes the middlewares from within the DMS service (if svc.service.func is used instead of regular svc.func)
		dmsSvc.SetService(svc)
	}

	if conf.CMPConfirmationMonitoringJob.Enabled {
		lMonitor := chelpers.SetupLogger(conf.Logs.Level, "DMS Manager", "CMP Confirmation Monitor")
		lMonitor.Info("CMP Confirmation Monitoring is enabled")
		monitorJob := jobs.NewCMPConfirmationMonitor(cmptxStorage, caService, cmpReporter, lMonitor)
		scheduler := jobs.NewJobScheduler(lMonitor, conf.CMPConfirmationMonitoringJob.Frequency, monitorJob)
		scheduler.Start()
	}

	return &svc, nil
}

func createCMPTransactionStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.CMPTransactionRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}
	cmptxStorage, err := engine.GetCMPTransactionStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get CMP transaction storage: %s", err)
	}
	return cmptxStorage, nil
}

func createDMSStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.DMSRepo, error) {
	storage, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}
	dmsStorage, err := storage.GetDMSStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get device storage: %s", err)
	}
	return dmsStorage, nil
}
