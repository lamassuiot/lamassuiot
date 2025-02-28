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

func AssembleVAServiceWithHTTPServer(conf config.VAconfig, caService services.CAService, serviceInfo models.APIServiceInfo) (*services.CRLService, *services.OCSPService, int, error) {
	crl, ocsp, err := AssembleVAService(conf, caService)
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

func AssembleVAService(conf config.VAconfig, caService services.CAService) (*services.CRLService, *services.OCSPService, error) {
	serviceID := "va"

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
		Logger:   lSvc,
		CAClient: caService,
		VARepo:   vaRoleRepo,
		Bucket:   (*blob.Bucket)(bucket),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CRL service: %s", err)
	}

	ocsp := beService.NewOCSPService(beService.OCSPServiceBuilder{
		Logger:   lSvc,
		CAClient: caService,
	})

	lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "VA", "Event Bus")
	lMessaging.Infof("Subscriber Event Bus is enabled")

	pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, serviceID, lMessaging)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
	}

	crlSvc := crl.(*beService.CRLServiceBackend)
	crl = eventpub.NewCRLEventPublisher(&eventpub.CloudEventMiddlewarePublisher{
		Publisher: pub,
		ServiceID: serviceID,
		Logger:    lMessaging,
	})(crl)

	crlSvc.SetService(crl)

	subscriber, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, serviceID, lMessaging)
	if err != nil {
		lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, nil, err
	}

	eventHandlers := handlers.NewVAEventHandler(lMessaging, crlSvc)
	subHandler, err := ceventbus.NewEventBusMessageHandler("VA-CA-DEFAULT", []string{"ca.#", "certificate.#"}, subscriber, lMessaging, *eventHandlers)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create Event Bus Subscription Handler: %s", err)
	}

	err = subHandler.RunAsync()
	if err != nil {
		lMessaging.Errorf("could not run Event Bus Subscription Handler: %s", err)
		return nil, nil, err
	}

	lJob := helpers.SetupLogger(conf.Logs.Level, "VA", "Service")
	frequency := conf.CRLMonitoringJob.Frequency

	blindPeriod, err := jobs.GetSchedulerPeriod(frequency)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse scheduler period: %s", err)
	}

	log.Infof("VA CRL Monitoring is enabled")
	monitorJob := jobs.NewVACrlMonitorJob(lJob, crl, blindPeriod)
	scheduler := jobs.NewJobScheduler(lJob, frequency, monitorJob)
	scheduler.Start()

	return &crl, &ocsp, nil
}
