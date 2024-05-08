package helpers

import (
	"context"
	"fmt"
	"io"
	"path"
	"runtime"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	headerextractors "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/basic-header-extractors"
	identityextractors "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/identity-extractors"
	"github.com/sirupsen/logrus"
)

var LogFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"src-call-id", "req-id", "service", "subsystem", "subsystem-provider"},
	CallerFirst:     true,
	CustomCallerFormatter: func(f *runtime.Frame) string {
		filename := path.Base(f.File)
		return fmt.Sprintf(" [%s %s():%d]", filename, f.Function, f.Line)
	},
}

func SetupLogger(currentLevel config.LogLevel, serviceID string, subsystem string) *logrus.Entry {
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

func ConfigureLogger(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	logger = configureLoggerWitSourceAndCallerID(ctx, logger)
	logger = configureLoggerWithRequestID(ctx, logger)
	return logger
}

func configureLoggerWitSourceAndCallerID(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	source := ""
	callID := ""

	sourceCtx := ctx.Value(string(headerextractors.CtxSource))
	if src, ok := sourceCtx.(string); ok {
		source = src
	}

	callerCtx := ctx.Value(string(identityextractors.CtxCallerID))
	if id, ok := callerCtx.(string); ok {
		callID = id
	}

	if source != "" || callID != "" {
		return logger.WithField("src-call-id", callID)
	}

	return logger
}

func configureLoggerWithRequestID(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	if logger.Logger.Level < logrus.DebugLevel {
		return logger
	}

	reqCtx := ctx.Value(headerextractors.CtxRequestID)
	if reqID, ok := reqCtx.(string); ok {
		return logger.WithField("req-id", reqID)
	}

	return logger.WithField("req-id", fmt.Sprintf("unset.%s", goid.NewV4UUID()))
}

func InitContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, headerextractors.CtxRequestID, fmt.Sprintf("internal.%s", goid.NewV4UUID()))
	return ctx
}
