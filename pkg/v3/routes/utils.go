package routes

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

func newHttpRouter(logger *logrus.Entry, routerEngine *gin.Engine, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
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
		srvExtraLog := ""
		if httpServerCfg.Authentication.MutualTLS.Enabled {
			srvExtraLog = "with mTLS enabled"

			valCAPool := x509.NewCertPool()

			vaCert, err := helpers.ReadCertificateFromFile(httpServerCfg.Authentication.MutualTLS.CACertificateFile)
			if err != nil {
				return fmt.Errorf("could not load CA cert used while validating mTLS requests: %s", err)
			}

			valCAPool.AddCert(vaCert)

			var clientAuth tls.ClientAuthType
			if httpServerCfg.Authentication.MutualTLS.ValidationMode == config.Any {
				clientAuth = tls.RequireAnyClientCert
				srvExtraLog = srvExtraLog + " using 'any' validation mode"
			} else if httpServerCfg.Authentication.MutualTLS.ValidationMode == config.Strict {
				clientAuth = tls.RequireAndVerifyClientCert
				srvExtraLog = srvExtraLog + " using 'strict' validation mode"
			} else if httpServerCfg.Authentication.MutualTLS.ValidationMode == "" {
				logger.Warnf("mutual TLS validation mode is empty. Defaulting to 'strict' validation")
				srvExtraLog = srvExtraLog + " using 'strict' validation mode"
				clientAuth = tls.RequireAndVerifyClientCert
			} else {
				logger.Warnf("mutual TLS validation mode not recognized. Defaulting to 'strict' validation")
				clientAuth = tls.RequireAndVerifyClientCert
				srvExtraLog = srvExtraLog + " using 'strict' validation mode"
			}

			if clientAuth == tls.RequireAndVerifyClientCert {
				logger.Debugf("mTLS requests will be accepted when client presents a certificate issued by CA with subject '%s'", vaCert.Subject.String())
			}

			server.TLSConfig = &tls.Config{
				ClientAuth: clientAuth,
				ClientCAs:  valCAPool,
			}
		}

		logger.Infof("HTTPS server listening on %s %s", addr, srvExtraLog)
		err := server.ListenAndServeTLS(httpServerCfg.CertFile, httpServerCfg.KeyFile)
		return err
	} else {
		logger.Infof("HTTP server listening on %s", addr)
		err := server.ListenAndServe()
		return err
	}
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}
