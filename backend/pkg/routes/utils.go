package routes

import (
	"bytes"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	httpserver "github.com/lamassuiot/lamassuiot/v4/core/pkg/http/server"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
)

func NewGinEngine(logger *logrus.Entry) *gin.Engine {
	return httpserver.NewGinEngine(logger, httpserver.Options{})
}

func RunHttpRouter(logger *logrus.Entry, routerEngine http.Handler, httpServerCfg cconfig.HttpServer, apiInfo models.APIServiceInfo, openApiContent []byte) (int, error) {
	return httpserver.RunHTTPRouter(logger, routerEngine, httpServerCfg, apiInfo, openApiContent, httpserver.Options{})
}

func LogRequest(logger *logrus.Entry, logResponse bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		rbw := &respBodyWriter{
			body:           &bytes.Buffer{},
			ResponseWriter: c.Writer,
		}
		c.Writer = rbw

		start := time.Now()
		c.Next()

		fields := make(map[string]any)
		logger.WithFields(fields).Infof("[Request] %v |%3d| %13v | %15s |%-7s %s",
			start.Format("2006/01/02 - 15:04:05"),
			c.Writer.Status(),
			time.Since(start),
			c.ClientIP(),
			c.Request.Method,
			c.Request.URL.Path,
		)
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

func InjectVersionIntoOpenAPI(openApiContent []byte, version string) []byte {
	return httpserver.InjectVersionIntoOpenAPI(openApiContent, version)
}
