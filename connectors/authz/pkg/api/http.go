package api

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	httpserver "github.com/lamassuiot/lamassuiot/v4/core/pkg/http/server"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
)

const httpServerTimeout = 10 * time.Second

var authzHTTPOptions = httpserver.Options{
	Recovery:          true,
	ReadHeaderTimeout: httpServerTimeout,
}

func newGinEngine(logger *logrus.Entry) *gin.Engine {
	return httpserver.NewGinEngine(logger, authzHTTPOptions)
}

func serverTLSConfig(logger *logrus.Entry, authentication cconfig.HttpServerAuthentication) *tls.Config {
	return httpserver.ServerTLSConfig(logger, authentication)
}

func newHTTPServer(logger *logrus.Entry, addr string, handler http.Handler, authentication cconfig.HttpServerAuthentication) *http.Server {
	return httpserver.NewHTTPServer(logger, addr, handler, authentication, authzHTTPOptions)
}

func healthGinHandler(info models.APIServiceInfo) gin.HandlerFunc {
	return httpserver.HealthGinHandler(info)
}

func openAPIGinHandler(openAPI []byte) gin.HandlerFunc {
	return httpserver.OpenAPIGinHandler(openAPI)
}

func injectVersionIntoOpenAPI(openAPI []byte, version string) []byte {
	return httpserver.InjectVersionIntoOpenAPI(openAPI, version)
}

func runHTTPRouter(logger *logrus.Entry, router http.Handler, cfg cconfig.HttpServer, info models.APIServiceInfo, openAPI []byte) (int, error) {
	port, _, err := runHTTPRouterWithShutdown(logger, router, cfg, info, openAPI)
	return port, err
}

func runHTTPRouterWithShutdown(logger *logrus.Entry, router http.Handler, cfg cconfig.HttpServer, info models.APIServiceInfo, openAPI []byte) (int, func(), error) {
	return httpserver.RunHTTPRouterWithShutdown(logger, router, cfg, info, openAPI, authzHTTPOptions)
}
