package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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

const httpServerTimeout = 10 * time.Second

func newGinEngine(logger *logrus.Entry) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DebugPrintRouteFunc = func(method, path, handler string, count int) { logger.Debugf("Endpoint: %-6s %s", method, path) }
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
		gin.Recovery(),
	)
	return router
}

func serverTLSConfig(logger *logrus.Entry, authentication cconfig.HttpServerAuthentication) *tls.Config {
	if !authentication.MutualTLS.Enabled {
		return nil
	}

	clientCAs := x509.NewCertPool()
	caCert, err := helpers.ReadCertificateFromFile(authentication.MutualTLS.CACertificateFile)
	if err != nil {
		logger.Warnf("could not load CA cert used while validating mTLS requests: %s", err)
	} else {
		clientCAs.AddCert(caCert)
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

func newHTTPServer(logger *logrus.Entry, addr string, handler http.Handler, authentication cconfig.HttpServerAuthentication) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       httpServerTimeout,
		ReadHeaderTimeout: httpServerTimeout,
		WriteTimeout:      httpServerTimeout,
		TLSConfig:         serverTLSConfig(logger, authentication),
	}
}

func healthHandler(info models.APIServiceInfo) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"health":     true,
			"version":    info.Version,
			"build":      info.BuildSHA,
			"build_time": info.BuildTime,
		})
	}
}

func injectVersionIntoOpenAPI(openAPI []byte, version string) []byte {
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

func runHTTPRouter(logger *logrus.Entry, router http.Handler, cfg cconfig.HttpServer, info models.APIServiceInfo, openAPI []byte) (int, error) {
	mux := http.NewServeMux()
	mux.Handle("/", router)
	mux.Handle("/health", healthHandler(info))
	if len(openAPI) > 0 {
		openAPI = injectVersionIntoOpenAPI(openAPI, info.Version)
		mux.HandleFunc("/openapi", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write(openAPI)
		})
	}
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.Port)
	server := newHTTPServer(logger, addr, mux, cfg.Authentication)
	if cfg.Protocol == cconfig.HTTPS {
		certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return -1, fmt.Errorf("load HTTPS server certificate and key: %w", err)
		}

		if server.TLSConfig == nil {
			server.TLSConfig = &tls.Config{}
		} else {
			server.TLSConfig = server.TLSConfig.Clone()
		}
		server.TLSConfig.Certificates = []tls.Certificate{certificate}
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return -1, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		var serveErr error
		if cfg.Protocol == cconfig.HTTPS {
			serveErr = server.ServeTLS(listener, "", "")
		} else {
			serveErr = server.Serve(listener)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Errorf("could not start HTTP server: %s", serveErr)
		}
	}()
	_ = info
	return port, nil
}
