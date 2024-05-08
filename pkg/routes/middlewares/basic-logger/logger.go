package basiclogger

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/sirupsen/logrus"
)

const (
	defaultLogFormat = "%s %-7s %s %s %3d %s [ %30v ] | %13v | \"%s\"\n"
)

type traceRequestWriter struct {
	logger *logrus.Entry
}

func (tr *traceRequestWriter) Write(p []byte) (n int, err error) {
	tr.logger.Debugf("%s", string(p))
	return len(p), nil
}

func UseLogger(logger *logrus.Entry) gin.HandlerFunc {
	return logRequest(logger)
}

func loggingWithReqBodyLog(param gin.LogFormatterParams) string {
	var statusColor, methodColor, resetColor string
	if param.IsOutputColor() {
		statusColor = param.StatusCodeColor()
		methodColor = param.MethodColor()
		resetColor = param.ResetColor()
	}

	return fmt.Sprintf(defaultLogFormat,
		methodColor, param.Method, resetColor,
		statusColor, param.StatusCode, resetColor,
		fmt.Sprintf("agent: \"%s\"", param.Request.UserAgent()),
		param.Latency,
		param.Path,
	)
}

func logRequest(logger *logrus.Entry) gin.HandlerFunc {
	formatter := loggingWithReqBodyLog

	return func(c *gin.Context) {
		lReq := helpers.ConfigureLogger(c, logger)
		out := &traceRequestWriter{logger: lReq}

		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		param := gin.LogFormatterParams{
			Request: c.Request,
			Keys:    c.Keys,
		}

		// Stop timer
		param.TimeStamp = time.Now()
		param.Latency = param.TimeStamp.Sub(start)

		param.ClientIP = c.ClientIP()
		param.Method = c.Request.Method
		param.StatusCode = c.Writer.Status()
		param.ErrorMessage = c.Errors.ByType(gin.ErrorTypePrivate).String()

		param.BodySize = c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}

		param.Path = path

		fmt.Fprint(out, formatter(param))
	}
}
