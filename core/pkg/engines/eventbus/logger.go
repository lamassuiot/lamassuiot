package eventbus

import (
	"github.com/ThreeDotsLabs/watermill"
	"github.com/sirupsen/logrus"
)

type messagingLogger struct {
	entry *logrus.Entry
}

func NewLoggerAdapter(l *logrus.Entry) watermill.LoggerAdapter {
	return &messagingLogger{
		entry: l,
	}
}

func (l *messagingLogger) Error(msg string, err error, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Error(msg, err)
}

func (l *messagingLogger) Info(msg string, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *messagingLogger) Debug(msg string, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *messagingLogger) Trace(msg string, fields watermill.LogFields) {
	l.entry.WithFields(logrus.Fields(fields)).Trace(msg)
}

func (l *messagingLogger) With(fields watermill.LogFields) watermill.LoggerAdapter {
	return &messagingLogger{
		entry: l.entry.WithFields(logrus.Fields(fields)),
	}
}
