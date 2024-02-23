package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/core/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/services"
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
