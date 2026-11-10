package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	basiclogger "github.com/lamassuiot/lamassuiot/v4/core/pkg/http/basiclogger"
	headerextractors "github.com/lamassuiot/lamassuiot/v4/core/pkg/http/headerextractors"
	identityextractors "github.com/lamassuiot/lamassuiot/v4/core/pkg/http/identityextractors"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/shared/http/pkg/utils/gindump"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"gopkg.in/yaml.v3"
)

type Options struct {
	Recovery          bool
	ReadHeaderTimeout time.Duration
}

func NewGinEngine(logger *logrus.Entry, options Options) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DebugPrintRouteFunc = func(method, path, handler string, count int) {
		logger.Debugf("Endpoint: %-6s %s", method, path)
	}

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowHeaders = []string{"*"}

	router := gin.New()
	router.Use(
		cors.New(corsConfig),
		otelgin.Middleware("gin-server"),
		headerextractors.RequestMetadataToContextMiddleware(logger),
		identityextractors.RequestMetadataToContextMiddleware(logger),
		basiclogger.UseLogger(logger),
		gindump.DumpWithOptions(true, true, true, true, func(dumpStr string) {
			logger.Trace(dumpStr)
		}),
	)
	if options.Recovery {
		router.Use(gin.Recovery())
	}
	return router
}

func ServerTLSConfig(logger *logrus.Entry, authentication cconfig.HttpServerAuthentication) *tls.Config {
	if !authentication.MutualTLS.Enabled {
		return nil
	}

	clientCAs := x509.NewCertPool()
	caCert, err := helpers.ReadCertificateFromFile(authentication.MutualTLS.CACertificateFile)
	if err != nil {
		logger.Warnf("could not load CA cert used while validating mTLS requests: %s", err)
	} else {
		clientCAs.AddCert(caCert)
		logger.Debugf("mTLS requests will be accepted when client presents a certificate issued by CA with subject '%s'", caCert.Subject.String())
	}

	clientAuth := tls.RequireAndVerifyClientCert
	switch authentication.MutualTLS.ValidationMode {
	case cconfig.Any:
		clientAuth = tls.RequireAnyClientCert
	case cconfig.Request:
		clientAuth = tls.RequestClientCert
	case cconfig.Strict, "":
		if authentication.MutualTLS.ValidationMode == "" {
			logger.Warnf("mutual TLS validation mode is empty. Defaulting to 'strict' validation")
		}
	default:
		logger.Warnf("mutual TLS validation mode not recognized. Defaulting to 'strict' validation")
	}

	return &tls.Config{
		ClientAuth: clientAuth,
		ClientCAs:  clientCAs,
		MaxVersion: tls.VersionTLS12,
	}
}

func NewHTTPServer(logger *logrus.Entry, addr string, handler nethttp.Handler, protocol cconfig.HTTPProtocol, authentication cconfig.HttpServerAuthentication, options Options) *nethttp.Server {
	var tlsConfig *tls.Config
	if protocol == cconfig.HTTPS {
		tlsConfig = ServerTLSConfig(logger, authentication)
	}

	return &nethttp.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: options.ReadHeaderTimeout,
		WriteTimeout:      10 * time.Second,
		TLSConfig:         tlsConfig,
	}
}

func HealthGinHandler(info models.APIServiceInfo) gin.HandlerFunc {
	return func(context *gin.Context) {
		context.JSON(nethttp.StatusOK, gin.H{
			"health":     true,
			"version":    info.Version,
			"build":      info.BuildSHA,
			"build_time": info.BuildTime,
		})
	}
}

func OpenAPIGinHandler(openAPI []byte) gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Data(nethttp.StatusOK, "application/yaml", openAPI)
	}
}

func InjectVersionIntoOpenAPI(openAPI []byte, version string) []byte {
	if len(openAPI) == 0 || version == "" {
		return openAPI
	}

	var spec map[string]any
	if err := yaml.Unmarshal(openAPI, &spec); err != nil {
		return openAPI
	}

	info, ok := spec["info"].(map[string]any)
	if !ok {
		return openAPI
	}
	info["version"] = version

	modified, err := yaml.Marshal(spec)
	if err != nil {
		return openAPI
	}
	return modified
}

func RunHTTPRouter(logger *logrus.Entry, router nethttp.Handler, cfg cconfig.HttpServer, info models.APIServiceInfo, openAPI []byte, options Options) (int, error) {
	port, _, err := RunHTTPRouterWithShutdown(logger, router, cfg, info, openAPI, options)
	return port, err
}

func RunHTTPRouterWithShutdown(logger *logrus.Entry, router nethttp.Handler, cfg cconfig.HttpServer, info models.APIServiceInfo, openAPI []byte, options Options) (int, func(), error) {
	mux := nethttp.NewServeMux()
	mux.Handle("/", router)
	mainLogger := logger
	if !cfg.HealthCheckLogging {
		nooutLogger := logrus.New()
		nooutLogger.Out = io.Discard
		mainLogger = nooutLogger.WithField("", "")
	}

	healthEngine := NewGinEngine(mainLogger, options)
	healthEngine.GET("/health", HealthGinHandler(info))
	mux.Handle("/health", healthEngine)
	if len(openAPI) > 0 {
		openAPI = InjectVersionIntoOpenAPI(openAPI, info.Version)
		openAPIEngine := NewGinEngine(mainLogger, options)
		openAPIEngine.GET("/openapi", OpenAPIGinHandler(openAPI))
		mux.Handle("/openapi", openAPIEngine)
	}

	addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.Port)
	httpServer := NewHTTPServer(logger, addr, mux, cfg.Protocol, cfg.Authentication, options)
	if cfg.Protocol == cconfig.HTTPS {
		certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return -1, nil, fmt.Errorf("load HTTPS server certificate and key: %w", err)
		}
		if httpServer.TLSConfig == nil {
			httpServer.TLSConfig = &tls.Config{}
		} else {
			httpServer.TLSConfig = httpServer.TLSConfig.Clone()
		}
		httpServer.TLSConfig.Certificates = []tls.Certificate{certificate}
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return -1, nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	var startup sync.WaitGroup
	startup.Add(1)
	serverErr := make(chan error, 1)
	go func() {
		if cfg.Protocol == cconfig.HTTPS {
			logger.Infof("HTTPS server listening on %s:%d %s", cfg.ListenAddress, port, mtlsStartupLog(cfg.Authentication))
		} else {
			logger.Infof("HTTP server listening on %s:%d", cfg.ListenAddress, port)
		}
		startup.Done()
		var serveErr error
		if cfg.Protocol == cconfig.HTTPS {
			serveErr = httpServer.ServeTLS(listener, "", "")
		} else {
			serveErr = httpServer.Serve(listener)
		}
		if serveErr != nil && serveErr != nethttp.ErrServerClosed {
			logger.Errorf("could not start HTTP server: %s", serveErr)
			serverErr <- serveErr
		}
	}()

	startup.Wait()
	readyContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case serveErr := <-serverErr:
		return -1, nil, serveErr
	case <-readyContext.Done():
		logger.Infof("HTTP server ready to accept requests")
	}

	shutdown := func() {
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = httpServer.Shutdown(shutdownContext)
	}
	return port, shutdown, nil
}

func mtlsStartupLog(authentication cconfig.HttpServerAuthentication) string {
	if !authentication.MutualTLS.Enabled {
		return ""
	}

	switch authentication.MutualTLS.ValidationMode {
	case cconfig.Any:
		return "with mTLS enabled using 'any' validation mode (at least one client certificate MUST be sent but wont be validated)"
	case cconfig.Request:
		return "with mTLS enabled using 'request' validation mode (client certificate will be request although not mandatory to be sent. Behaves like optional mTLS)"
	case cconfig.Strict, "":
		return "with mTLS enabled using 'strict' validation mode"
	default:
		return "with mTLS enabled using 'strict' validation mode"
	}
}
