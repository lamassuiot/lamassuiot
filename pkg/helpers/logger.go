package helpers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/gin-gonic/gin"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

var LogFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"req-id", "service", "subsystem", "subsystem-provider"},
	CallerFirst:     true,
	CustomCallerFormatter: func(f *runtime.Frame) string {
		filename := path.Base(f.File)
		return fmt.Sprintf(" [%s %s():%d]", filename, f.Function, f.Line)
	},
}

func ConfigureLogger(currentLevel config.LogLevel, serviceID string, subsystem string) *logrus.Entry {
	var err error
	logger := logrus.New()
	logger.SetFormatter(LogFormatter)
	lSubsystem := logger.WithFields(logrus.Fields{
		"service":   serviceID,
		"subsystem": subsystem,
	})

	if currentLevel == config.None {
		lSubsystem.Infof("subsystem logging will be disabled")
		lSubsystem.Logger.SetOutput(io.Discard)
	} else {
		level := logrus.GetLevel()

		if currentLevel != "" {
			level, err = logrus.ParseLevel(string(currentLevel))
			if err != nil {
				logrus.Warnf("'%s' invalid '%s' log level. Defaulting to global log level", subsystem, currentLevel)
			}
		} else {
			logrus.Warnf("'%s' log level not set. Defaulting to global log level", subsystem)
		}

		lSubsystem.Logger.SetLevel(level)
	}

	lSubsystem.Infof("log level set to '%s'", lSubsystem.Logger.GetLevel())
	return lSubsystem
}

var HTTPRequestID = "HTTPRequestID"

func ConfigureLoggerWithRequestID(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	if logger.Logger.Level < logrus.DebugLevel {
		return logger
	}

	reqCtx := ctx.Value(HTTPRequestID)
	if reqID, ok := reqCtx.(string); ok {
		return logger.WithField("req-id", reqID)
	}

	return logger.WithField("req-id", fmt.Sprintf("unset.%s", goid.NewV4UUID()))
}

func InitContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "req-id", fmt.Sprintf("internal.%s", goid.NewV4UUID()))
	return ctx
}

func ConfigureContextWithRequest(ctx *gin.Context, headers http.Header) {
	reqID := headers.Get("x-request-id")
	if reqID != "" {
		ctx.Set(HTTPRequestID, reqID)
	}

	source := headers.Get(models.HttpSourceHeader)
	if source != "" {
		ctx.Set(models.ContextSourceKey, source)
	}
}
