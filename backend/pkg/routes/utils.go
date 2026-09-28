package routes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	headerextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/basic-header-extractors"
	basiclogger "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/basic-logger"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/utils/gindump"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func NewGinEngine(logger *logrus.Entry, validators ...*identityextractors.JWTValidator) *gin.Engine {
	return NewGinEngineWithCORS(logger, nil, validators...)
}

func NewGinEngineWithCORS(logger *logrus.Entry, allowedOrigins []string, validators ...*identityextractors.JWTValidator) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		logger.Debugf("Endpoint: %-6s %s", httpMethod, absolutePath)
	}

	router := gin.New()
	middlewares := make([]gin.HandlerFunc, 0, 7)
	if len(allowedOrigins) > 0 && validCORSOrigins(allowedOrigins) {
		corsConfig := cors.DefaultConfig()
		corsConfig.AllowOrigins = append([]string(nil), allowedOrigins...)
		corsConfig.AllowHeaders = []string{"Accept", "Authorization", "Content-Length", "Content-Type", "Origin", "X-LMS-Tenant-ID", "X-Request-ID", "X-Tenant-ID"}
		middlewares = append(middlewares, cors.New(corsConfig))
	}
	middlewares = append(middlewares,
		otelgin.Middleware("gin-server"),
		headerextractors.RequestMetadataToContextMiddleware(logger),
		identityextractors.RequestMetadataToContextMiddleware(logger, validators...),
		basiclogger.UseLogger(logger),
		gindump.DumpWithOptions(true, true, true, true, func(dumpStr string) {
			logger.Trace(dumpStr)
		}),
	)
	router.Use(middlewares...)

	return router
}

func validCORSOrigins(origins []string) bool {
	if len(origins) == 0 {
		return false
	}
	for _, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil || strings.TrimSpace(origin) != origin || strings.Contains(origin, "*") || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || origin != parsed.Scheme+"://"+parsed.Host {
			return false
		}
	}
	return true
}

func RunHttpRouter(logger *logrus.Entry, routerEngine http.Handler, httpServerCfg cconfig.HttpServer, apiInfo models.APIServiceInfo) (int, error) {
	port, _, err := RunHttpRouterWithShutdown(logger, routerEngine, httpServerCfg, apiInfo)
	return port, err
}

func RunHttpRouterWithShutdown(logger *logrus.Entry, routerEngine http.Handler, httpServerCfg cconfig.HttpServer, apiInfo models.APIServiceInfo) (int, func() error, error) {
	if err := validateHTTPServerSecurity(httpServerCfg); err != nil {
		return -1, nil, err
	}
	hCheckRoute := controllers.NewHealthCheckRoute(apiInfo)
	mainLogger := logger
	if !httpServerCfg.HealthCheckLogging {
		nooutLogger := logrus.New()
		nooutLogger.Out = io.Discard

		mainLogger = nooutLogger.WithField("", "")
	}

	healthEngine := NewGinEngineWithCORS(mainLogger, httpServerCfg.CORSAllowedOrigins)
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
		return -1, nil, err
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
		if httpServerCfg.Protocol == cconfig.HTTPS {
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
				if httpServerCfg.Authentication.MutualTLS.ValidationMode == cconfig.Any {
					clientAuth = tls.RequireAnyClientCert
					srvExtraLog = srvExtraLog + " using 'any' validation mode (at least one client certificate MUST be sent but wont be validated)"
				} else if httpServerCfg.Authentication.MutualTLS.ValidationMode == cconfig.Strict {
					clientAuth = tls.RequireAndVerifyClientCert
					srvExtraLog = srvExtraLog + " using 'strict' validation mode"
				} else if httpServerCfg.Authentication.MutualTLS.ValidationMode == cconfig.Request {
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
		return -1, nil, err
	}

	if !httpServerCfg.InternalListener.Enabled {
		return usedPort, server.Close, nil
	}
	internalServer, err := runInternalListener(logger, mainEngine, httpServerCfg)
	if err != nil {
		server.Close()
		return -1, nil, err
	}
	return usedPort, func() error {
		internalErr := internalServer.Close()
		if err := server.Close(); err != nil {
			return err
		}
		return internalErr
	}, nil
}

// runInternalListener serves the same routes on a second HTTPS port that only
// accepts client certificates issued by the internal platform CA. Requests
// accepted there are marked as internal service calls.
func runInternalListener(logger *logrus.Entry, handler http.Handler, httpServerCfg cconfig.HttpServer) (*http.Server, error) {
	cfg := httpServerCfg.InternalListener
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ClientCAFile == "" {
		return nil, fmt.Errorf("internal listener requires cert_file, key_file and client_ca_file")
	}
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("could not read internal client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("internal client CA file contains no certificates")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", httpServerCfg.ListenAddress, cfg.Port))
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:      tenantcontext.MarkInternalServiceRequest(handler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
			MinVersion: tls.VersionTLS12,
		},
	}
	logger.Infof("internal HTTPS listener on %s (mTLS, internal CA)", listener.Addr())
	go func() {
		if err := server.ServeTLS(listener, cfg.CertFile, cfg.KeyFile); err != nil && err != http.ErrServerClosed {
			logger.Errorf("internal listener stopped: %s", err)
		}
	}()
	return server, nil
}

func validateHTTPServerSecurity(httpServerCfg cconfig.HttpServer) error {
	if httpServerCfg.Authentication.MutualTLS.Enabled && httpServerCfg.Protocol != cconfig.HTTPS {
		return fmt.Errorf("mutual TLS authentication requires HTTPS")
	}
	for _, origin := range httpServerCfg.CORSAllowedOrigins {
		if !validCORSOrigins([]string{origin}) {
			return fmt.Errorf("invalid CORS origin %q; configure an exact http(s) origin without path or wildcard", origin)
		}
	}
	return nil
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

		latency := time.Since(start)
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
