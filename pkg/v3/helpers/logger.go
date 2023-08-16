package helpers

import (
	"io"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/sirupsen/logrus"
)

var logFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"subsystem", "subsystem-provider", "req"},
}

func ConfigureLogger(defaultLevel logrus.Level, currentLevel config.LogLevel, subsystem string) *logrus.Entry {
	var err error
	logger := logrus.New()
	logger.SetFormatter(logFormatter)
	lSubystem := logger.WithField("subsystem", subsystem)

	if currentLevel == config.None {
		lSubystem.Infof("subsystem logging will be disabled")
		lSubystem.Logger.SetOutput(io.Discard)
	} else {
		level := defaultLevel

		if currentLevel != "" {
			level, err = logrus.ParseLevel(string(currentLevel))
			if err != nil {
				logrus.Warnf("'%s' invalid '%s' log level. Defaulting to global log level", subsystem, currentLevel)
			}
		} else {
			logrus.Warnf("'%s' log level not set. Defaulting to global log level", subsystem)
		}

		lSubystem.Logger.SetLevel(level)
	}
	lSubystem.Infof("log level set to '%s'", lSubystem.Logger.GetLevel())
	return lSubystem
}
