package utils

import (
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type StandardGoKitLogToGoLogAdapter interface {
	Printf(format string, v ...interface{})
	Verbose() bool
}

type CustomLogger struct {
	logger log.Logger
}

func NewGoKitLogToGoLogAdapter(logger log.Logger) StandardGoKitLogToGoLogAdapter {
	return &CustomLogger{
		logger: logger,
	}
}

func (l *CustomLogger) Printf(format string, v ...interface{}) {
	level.Debug(l.logger).Log("msg", fmt.Sprintf(format, v))
}
func (l *CustomLogger) Verbose() bool {
	return true
}
