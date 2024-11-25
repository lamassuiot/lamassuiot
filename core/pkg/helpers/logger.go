package helpers

import (
	"context"
	"fmt"
	"io"
	"path"
	"runtime"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
)

const CtxSource = "REQ_SOURCE"
const CtxRequestID = "REQ_ID"

const CtxAuthMode = "REQ_AUTH_MODE"
const CtxAuthID = "REQ_AUTH_ID"

var LogFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"src", "auth-mode", "auth-id", "req-id", "service", "subsystem", "subsystem-provider"},
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
	authMode := ""
	authID := ""

	sourceCtx := ctx.Value(string(CtxSource))
	if src, ok := sourceCtx.(string); ok {
		source = src
	}

	authIDCtx := ctx.Value(string(CtxAuthID))
	if id, ok := authIDCtx.(string); ok {
		authID = id
	}

	authModeCtx := ctx.Value(string(CtxAuthMode))
	if mode, ok := authModeCtx.(string); ok {
		authMode = mode
	}

	logger = logger.WithField("src", source)
	logger = logger.WithField("auth-mode", authMode)
	logger = logger.WithField("auth-id", authID)

	return logger
}

func configureLoggerWithRequestID(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	if logger.Logger.Level < logrus.DebugLevel {
		return logger
	}

	reqCtx := ctx.Value(CtxRequestID)
	if reqID, ok := reqCtx.(string); ok {
		return logger.WithField("req-id", reqID)
	}

	return logger.WithField("req-id", fmt.Sprintf("unset.%s", goid.NewV4UUID()))
}

func InitContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, CtxRequestID, fmt.Sprintf("internal.%s", goid.NewV4UUID()))
	return ctx
}
