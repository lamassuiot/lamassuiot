package routes

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	gindump "github.com/haritzsaiz/gin-dump"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

type traceRequestWriter struct {
	logger *logrus.Entry
}

func (tr *traceRequestWriter) Write(p []byte) (n int, err error) {
	logReq := string(p)
	logReq = strings.ReplaceAll(logReq, "\n", "")
	splitter := strings.SplitAfterN(logReq, "|", 2)
	if len(splitter) == 2 {
		tr.logger.Debugf("%s", splitter[1])
	} else {
		tr.logger.Debugf("%s", string(p))
	}
	return len(p), nil
}

func newGinEngine(logger *logrus.Entry) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		logger.Debugf("Endpoint: %-6s %s", httpMethod, absolutePath)
	}

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowHeaders = []string{"*"}

	router := gin.New()
	router.Use(cors.New(corsConfig), gindump.DumpWithOptions(true, true, true, true, func(dumpStr string) {
		logger.Trace(dumpStr)
	}), gin.LoggerWithWriter(&traceRequestWriter{logger: logger}), gin.Recovery())

	return router
}

func RunHttpRouter(logger *logrus.Entry, routerEngine *gin.Engine, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	hCheckRoute := controllers.NewHealthCheckRoute(apiInfo)
	routerEngine.GET("/health", hCheckRoute.HealthCheck)

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
				logger.Warnf("could not load CA cert used while validating mTLS requests: %s", err)
			} else {
				valCAPool.AddCert(vaCert)
			}

			var clientAuth tls.ClientAuthType
			if httpServerCfg.Authentication.MutualTLS.ValidationMode == config.Any {
				clientAuth = tls.RequireAnyClientCert
				srvExtraLog = srvExtraLog + " using 'any' validation mode (at least one client certificate MUST be sent but wont be validated)"
			} else if httpServerCfg.Authentication.MutualTLS.ValidationMode == config.Strict {
				clientAuth = tls.RequireAndVerifyClientCert
				srvExtraLog = srvExtraLog + " using 'strict' validation mode"
			} else if httpServerCfg.Authentication.MutualTLS.ValidationMode == config.Request {
				clientAuth = tls.RequestClientCert
				srvExtraLog = srvExtraLog + " using 'request' validation mode (client certificate will be request altgouh not mandatory to be sent. Behaves like optional mTLS)"
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
		if err != nil {
			logger.Fatalf("could not start http server: %s", err)
		}

		return nil
	} else {
		logger.Infof("HTTP server listening on %s", addr)
		err := server.ListenAndServe()
		if err != nil {
			logger.Fatalf("could not start http server: %s", err)
		}

		return nil
	}
}
