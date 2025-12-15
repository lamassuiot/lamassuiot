package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	fssBuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/fs-storage/builder"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	beService "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/handlers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	ceventbus "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	log "github.com/sirupsen/logrus"
	"gocloud.dev/blob"
)

var serviceID = "va"

func AssembleVAServiceWithHTTPServer(conf config.VAconfig, caService services.CAService, kmsService services.KMSService, serviceInfo models.APIServiceInfo) (*services.CRLService, *services.OCSPService, int, error) {
	crl, ocsp, err := AssembleVAService(conf, caService, kmsService)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble VA Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "VA", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewValidationRoutes(lHttp, httpGrp, *ocsp, *crl)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not run VA http server: %s", err)
	}

	return crl, ocsp, port, nil
}

func AssembleVAService(conf config.VAconfig, caService services.CAService, kmsService services.KMSService) (*services.CRLService, *services.OCSPService, error) {

	lSvc := helpers.SetupLogger(conf.Logs.Level, "VA", "Service")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "VA", "Storage")

	storage, err := builder.BuildStorageEngine(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	vaRoleRepo, err := storage.GetVARoleStorage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get device storage: %s", err)
	}

	bucket, err := fssBuilder.BuildFSStorageEngine(lStorage, conf.FilesystemStorage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create filesystem storage engine: %s", err)
	}

	crl, err := beService.NewCRLService(beService.CRLServiceBuilder{
		Logger:    lSvc,
		CAClient:  caService,
		KMSClient: kmsService,
		VARepo:    vaRoleRepo,
		VADomains: conf.VADomains,
		Bucket:    (*blob.Bucket)(bucket),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CRL service: %s", err)
	}

	ocsp := beService.NewOCSPService(beService.OCSPServiceBuilder{
		Logger:    lSvc,
		CAClient:  caService,
		KMSClient: kmsService,
	})

	crlSvc := crl.(*beService.CRLServiceBackend)

	if conf.PublisherEventBus.Enabled {
		crl, err = createPublisherEventBus(conf, crl)
		if err != nil {
			return nil, nil, err
		}

		//this utilizes the middlewares from within the CRL service (if svc.service.func is used instead of regular svc.func)
		crlSvc.SetService(crl)
	}

	if conf.SubscriberEventBus.Enabled {
		err := createSubscriberEventBus(conf, crlSvc)
		if err != nil {
			return nil, nil, err
		}
	}

	if conf.CRLMonitoringJob.Enabled {
		err := createCRLMonitoringJob(conf, crl)
		if err != nil {
			return nil, nil, err
		}
	}

	return &crl, &ocsp, nil
}

func createPublisherEventBus(conf config.VAconfig, crl services.CRLService) (services.CRLService, error) {

	lMessaging := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "VA", "Event Bus")
	lMessaging.Infof("Publisher Event Bus is enabled")
	pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, serviceID, lMessaging)
	if err != nil {
		return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
	}

	crl = eventpub.NewCRLEventPublisher(&eventpub.CloudEventPublisher{
		Publisher: pub,
		ServiceID: serviceID,
		Logger:    lMessaging,
	})(crl)

	return crl, nil
}

func createSubscriberEventBus(conf config.VAconfig, crlSvc *beService.CRLServiceBackend) error {
	lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "VA", "Event Bus")

	if conf.SubscriberEventBus.Enabled && !conf.SubscriberDLQEventBus.Enabled {
		lMessaging.Fatalf("Subscriber Event Bus is enabled but DLQ is not enabled. This is not supported. Exiting")
	}

	if conf.SubscriberEventBus.Enabled && conf.SubscriberDLQEventBus.Enabled {
		lMessaging.Infof("Subscriber Event Bus is enabled")

		dlqPublisher, err := eventbus.NewEventBusPublisher(conf.SubscriberDLQEventBus, serviceID, lMessaging)
		if err != nil {
			return fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		subscriber, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, serviceID, lMessaging)
		if err != nil {
			lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
			return err
		}

		eventHandlers := handlers.NewVAEventHandler(lMessaging, crlSvc)
		subHandler, err := ceventbus.NewEventBusMessageHandler("VA-CA-DEFAULT", []string{"ca.#", "certificate.#"}, dlqPublisher, subscriber, lMessaging, *eventHandlers)
		if err != nil {
			return fmt.Errorf("could not create Event Bus Subscription Handler: %s", err)
		}

		err = subHandler.RunAsync()
		if err != nil {
			lMessaging.Errorf("could not run Event Bus Subscription Handler: %s", err)
			return err
		}
	}

	return nil
}

func createCRLMonitoringJob(conf config.VAconfig, crl services.CRLService) error {

	log.Infof("VA CRL Monitoring is enabled")
	lJob := helpers.SetupLogger(conf.Logs.Level, "VA", "Service")

	frequency := conf.CRLMonitoringJob.Frequency
	blindPeriod, err := jobs.GetSchedulerPeriod(frequency)
	if err != nil {
		return fmt.Errorf("could not parse scheduler period: %s", err)
	}

	monitorJob := jobs.NewVACrlMonitorJob(lJob, crl, blindPeriod)
	scheduler := jobs.NewJobScheduler(lJob, frequency, monitorJob)
	scheduler.Start()

	return nil
}
