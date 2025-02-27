package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func AssembleVAServiceWithHTTPServer(conf config.VAconfig, caService services.CAService, serviceInfo models.APIServiceInfo) (*services.CRLService, *services.OCSPService, int, error) {
	crl, ocsp, err := AssembleVAService(conf, caService)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble VA Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "VA", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")

	r := controllers.NewBackendVAHttpRoutes(lHttp, *ocsp, *crl)
	routes.NewVAHTTPLayer(lHttp, httpGrp, r, conf.Server.Authorization)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not run VA http server: %s", err)
	}

	return crl, ocsp, port, nil
}

func AssembleVAService(conf config.VAconfig, caService services.CAService) (*services.CRLService, *services.OCSPService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "VA", "Service")

	crl := lservices.NewCRLService(lservices.CRLServiceBuilder{
		Logger:    lSvc,
		CAClient:  caService,
		VADomains: conf.VADomains,
	})

	ocsp := lservices.NewOCSPService(lservices.OCSPServiceBuilder{
		Logger:   lSvc,
		CAClient: caService,
	})

	return &crl, &ocsp, nil
}
