package lamassu

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/routes"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

func AssembleVAServiceWithHTTPServer(conf config.VAconfig, caService services.CAService, serviceInfo models.APIServiceInfo) (*services.CRLService, *services.OCSPService, int, error) {
	crl, ocsp, err := AssembleVAService(conf, caService)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble VA Service. Exiting: %s", err)
	}

	lHttp := helpers.ConfigureLogger(conf.Server.LogLevel, "HTTP Server")

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
	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")

	crl := services.NewCRLService(services.CRLServiceBuilder{
		Logger:   lSvc,
		CAClient: caService,
	})

	ocsp := services.NewOCSPService(services.OCSPServiceBuilder{
		Logger:   lSvc,
		CAClient: caService,
	})

	return &crl, &ocsp, nil
}
