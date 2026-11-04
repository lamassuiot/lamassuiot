package api

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func newGinEngine(logger *logrus.Entry) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DebugPrintRouteFunc = func(method, path, handler string, count int) { logger.Debugf("Endpoint: %-6s %s", method, path) }
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowHeaders = []string{"*"}
	router := gin.New()
	router.Use(cors.New(corsConfig), otelgin.Middleware("gin-server"), gin.LoggerWithWriter(logger.Writer()), gin.Recovery())
	return router
}

func runHTTPRouter(logger *logrus.Entry, router http.Handler, cfg cconfig.HttpServer, info models.APIServiceInfo, openAPI []byte) (int, error) {
	mux := http.NewServeMux()
	mux.Handle("/", router)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	if len(openAPI) > 0 {
		mux.HandleFunc("/openapi", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write(openAPI)
		})
	}
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return -1, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Addr: addr, Handler: mux}
	go func() {
		var serveErr error
		if cfg.Protocol == cconfig.HTTPS {
			serveErr = server.ServeTLS(listener, cfg.CertFile, cfg.KeyFile)
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
