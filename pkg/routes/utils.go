package routes

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
)

func newHttpRouter(routerEngine *gin.Engine, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowHeaders = []string{"*"}

	routerEngine.Use(cors.New(corsConfig))

	hcheckRoute := controllers.NewHealthCheckRoute(apiInfo)
	routerEngine.GET("/health", hcheckRoute.HealtCheck)

	addr := fmt.Sprintf("%s:%d", httpServerCfg.ListenAddress, httpServerCfg.Port)

	server := http.Server{
		Addr:    addr,
		Handler: routerEngine,
	}

	if httpServerCfg.Protocol == config.HTTPS {
		if httpServerCfg.Authentication.MutualTLS.Enabled {
			valCAPool := x509.NewCertPool()

			vaCert, err := helppers.ReadCertificateFromFile(httpServerCfg.Authentication.MutualTLS.CACertificateFile)
			if err != nil {
				return fmt.Errorf("could not load CA cert used while validating mTLS requests: %s", err)
			}

			valCAPool.AddCert(vaCert)

			server.TLSConfig = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  valCAPool,
			}
		}

		err := server.ListenAndServeTLS(httpServerCfg.CertFile, httpServerCfg.KeyFile)
		return err
	} else {
		err := server.ListenAndServe()
		return err
	}
}
