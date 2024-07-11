package routes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	headerextractors "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/basic-header-extractors"
	basiclogger "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/basic-logger"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/gindump"
	identityextractors "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/identity-extractors"
	"github.com/sirupsen/logrus"
)

func NewGinEngine(logger *logrus.Entry) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		logger.Debugf("Endpoint: %-6s %s", httpMethod, absolutePath)
	}

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowHeaders = []string{"*"}

	router := gin.New()
	router.Use(
		cors.New(corsConfig),
		headerextractors.RequestMetadataToContextMiddleware(logger),
		identityextractors.RequestMetadataToContextMiddleware(logger),
		basiclogger.UseLogger(logger),
		gindump.DumpWithOptions(true, true, true, true, func(dumpStr string) {
			logger.Trace(dumpStr)
		}),
		ErrorToStatusCodeMiddleware(logger),
	)

	return router
}

func RunHttpRouter(logger *logrus.Entry, routerEngine http.Handler, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) (int, error) {
	hCheckRoute := controllers.NewHealthCheckRoute(apiInfo)
	mainLogger := logger
	if !httpServerCfg.HealthCheckLogging {
		nooutLogger := logrus.New()
		nooutLogger.Out = io.Discard

		mainLogger = nooutLogger.WithField("", "")
	}

	healthEngine := NewGinEngine(mainLogger)
	healthEngine.GET("/health", hCheckRoute.HealthCheck)

	mainEngine := http.NewServeMux()
	mainEngine.Handle("/", routerEngine)
	mainEngine.Handle("/health", healthEngine)

	addr := fmt.Sprintf("%s:%d", httpServerCfg.ListenAddress, httpServerCfg.Port)

	t := time.Second * 10
	server := http.Server{
		Addr:         addr,
		Handler:      mainEngine,
		ReadTimeout:  t,
		WriteTimeout: t,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", httpServerCfg.ListenAddress, httpServerCfg.Port))
	if err != nil {
		return -1, err
	}

	usedPort := listener.Addr().(*net.TCPAddr).Port

	wg := new(sync.WaitGroup)
	wg.Add(1) // add `1` goroutines to finish
	startLaunching := func() {
		wg.Done()
	}

	httpErrChan := make(chan error, 1)

	if strings.HasSuffix(addr, ":0") {
		addr = strings.ReplaceAll(addr, ":0", "")
	}

	go func() {
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
					srvExtraLog = srvExtraLog + " using 'request' validation mode (client certificate will be request although not mandatory to be sent. Behaves like optional mTLS)"
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
					MaxVersion: tls.VersionTLS12,
				}
			}

			logger.Infof("HTTPS server listening on %s:%d %s", addr, usedPort, srvExtraLog)
			startLaunching()
			err := server.ServeTLS(listener, httpServerCfg.CertFile, httpServerCfg.KeyFile)
			if err != nil {
				logger.Errorf("could not start http server: %s", err)
				httpErrChan <- err
			}
		} else {
			logger.Infof("HTTP server listening on %s:%d", addr, usedPort)
			startLaunching()
			err := server.Serve(listener)
			if err != nil {
				logger.Errorf("could not start http server: %s", err)
				httpErrChan <- err
			}
		}
	}()

	// Create a context with a timeout of 3 seconds. If in 3 seconds of starting the HTTP server
	// no error is received, we will mark the HTTP server as RUNNING
	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	wg.Wait()

	select {
	case <-ctxTimeout.Done():
		logger.Info("HTTP server ready to accept requests")
	case err := <-httpErrChan:
		return -1, err
	}

	return usedPort, nil
}

func ErrorToStatusCodeMiddleware(logger *logrus.Entry) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		for _, ginErr := range c.Errors {
			err := ginErr.Err
			switch typedErr := err.(type) {
			case errs.HttpAPIError:
				c.JSON(typedErr.Status, gin.H{"err": typedErr.Msg})
			default:
				c.JSON(500, gin.H{"err": err.Error()})
			}
			return
		}
	}
}

type respBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w respBodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func LogRequest(logger *logrus.Entry, logResponse bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		rbw := &respBodyWriter{
			body:           bytes.NewBufferString(""),
			ResponseWriter: c.Writer,
		}
		c.Writer = rbw

		start := time.Now()

		c.Next()

		latency := time.Now().Sub(start)
		fields := make(map[string]interface{})

		logger.WithFields(fields).Infof("[Request] %v |%3d| %13v | %15s |%-7s %s",
			start.Format("2006/01/02 - 15:04:05"),
			c.Writer.Status(),
			latency,
			c.ClientIP(),
			c.Request.Method,
			c.Request.URL.Path,
		)
	}
}
