package servicebuilder

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	auditpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// ServiceConfig is the minimal constraint required by Run to bootstrap a service.
type ServiceConfig interface {
	GetLogs() cconfig.Logging
}

// Run loads config of type Conf, sets up logging, dumps config at debug level,
// calls assembleFn, then blocks forever. It is the standard entry point for all
// service binaries.
func Run[Conf ServiceConfig](serviceInfo models.APIServiceInfo, assembleFn func(conf Conf, serviceInfo models.APIServiceInfo) error) {
	log.SetFormatter(helpers.LogFormatter)

	conf, err := cconfig.LoadConfig[Conf](nil)
	if err != nil {
		log.Fatalf("could not load config: %s", err)
	}

	derefConf := *conf
	globalLogLevel, err := log.ParseLevel(string(derefConf.GetLogs().Level))
	if err != nil {
		log.Warn("unknown log level, defaulting to 'info'")
		globalLogLevel = log.InfoLevel
	}
	log.SetLevel(globalLogLevel)
	log.Infof("global log level set to '%s'", globalLogLevel)

	if confBytes, err := yaml.Marshal(conf); err == nil {
		log.Debugf("===================================================")
		log.Debugf("%s", confBytes)
		log.Debugf("===================================================")
	}

	if err := assembleFn(derefConf, serviceInfo); err != nil {
		log.Fatalf("could not run service: %s", err)
	}

	forever := make(chan struct{})
	<-forever
}

// ApplyMiddlewares wires the standard OTel → EventPub → AuditPub middleware
// chain onto svc. setService is called after each wrap so the concrete backend
// keeps its inner self-reference current.
//
// otelFn is always applied.
// eventFn and auditFn are applied only when publisherConf.Enabled is true.
func ApplyMiddlewares[S any](
	name string,
	serviceID string,
	publisherConf cconfig.EventBusEngine,
	svc S,
	setService func(S),
	otelFn func(S) S,
	eventFn func(S, eventpub.ICloudEventPublisher) S,
	auditFn func(S, auditpub.AuditPublisher) S,
	lEvent *log.Entry,
	lAudit *log.Entry,
) (S, error) {
	svc = otelFn(svc)
	setService(svc)

	if publisherConf.Enabled {
		pub, err := eventbus.NewEventBusPublisher(publisherConf, serviceID, lEvent)
		if err != nil {
			return svc, fmt.Errorf("could not create %s event bus publisher: %w", name, err)
		}

		ep := &eventpub.CloudEventPublisher{Publisher: pub, ServiceID: serviceID, Logger: lEvent}
		ap := &eventpub.CloudEventPublisher{Publisher: pub, ServiceID: serviceID, Logger: lAudit}

		svc = eventFn(svc, ep)
		svc = auditFn(svc, *auditpub.NewAuditPublisher(ap))
		setService(svc)
	}

	return svc, nil
}
