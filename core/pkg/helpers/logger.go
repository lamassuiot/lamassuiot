package helpers

import (
	"context"
	"fmt"
	"io"
	"path"
	"runtime"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/trace"
)

var LogFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"src", "auth-mode", "auth-id", "trace-id", "span-id", "service", "subsystem", "subsystem-provider"},
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
		// Add the hook to the local logger instance,
		// so entries written through lSubsystem are actually forwarded to OTEL.
		hook := otellogrus.NewHook(serviceID, otellogrus.WithLoggerProvider(global.GetLoggerProvider()))
		logger.AddHook(hook)

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

	sourceCtx := ctx.Value(core.LamassuContextKeySource)
	if src, ok := sourceCtx.(string); ok {
		source = src
	}

	authIDCtx := ctx.Value(core.LamassuContextKeyAuthID)
	if id, ok := authIDCtx.(string); ok {
		authID = id
	}

	authModeCtx := ctx.Value(core.LamassuContextKeyAuthType)
	if mode, ok := authModeCtx.(string); ok {
		authMode = mode
	}

	logger = logger.WithField("src", source)
	logger = logger.WithField("auth-type", authMode)
	logger = logger.WithField("auth-id", authID)

	if authCtx := ctx.Value(core.LamassuContextKeyAuthContext); authCtx != nil {
		logger = logger.WithField("auth-context", authCtx)
	}

	return logger
}

func configureLoggerWithRequestID(ctx context.Context, logger *logrus.Entry) *logrus.Entry {
	spanCtx := trace.SpanFromContext(ctx).SpanContext()
	if spanCtx.HasTraceID() {
		return logger.WithField("trace-id", spanCtx.TraceID().String())
	}

	if spanCtx.HasSpanID() {
		return logger.WithField("span-id", spanCtx.SpanID().String())
	}

	if requestID, ok := ctx.Value(core.LamassuContextKeyRequestID).(string); ok && requestID != "" {
		return logger.WithField("trace-id", requestID)
	}

	return logger
}

func InitContext() context.Context {
	return context.Background()
}

// InitJobContext creates a root context for a scheduled job, starting an OTel
// span with the given operationName. The caller must defer the returned func to
// end the span. jobID is used as the auth-id in log fields.
func InitJobContext(jobID string, operationName string) (context.Context, func()) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, core.LamassuContextKeyAuthType, "job")
	ctx = context.WithValue(ctx, core.LamassuContextKeyAuthID, jobID)
	ctx, span := otel.GetTracerProvider().Tracer("job-scheduler").Start(ctx, operationName)
	return ctx, func() { span.End() }
}
