package api

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
	gormlogger "gorm.io/gorm/logger"
)

// GormLogger bridges GORM's logger interface to a logrus.Entry.
// https://www.soberkoder.com/go-gorm-logging/
type GormLogger struct {
	Logger *logrus.Entry
}

func NewGormLogger(logger *logrus.Entry) *GormLogger {
	return &GormLogger{Logger: logger}
}

func (l *GormLogger) LogMode(_ gormlogger.LogLevel) gormlogger.Interface {
	newlogger := *l
	return &newlogger
}

func (l *GormLogger) Info(ctx context.Context, str string, rest ...interface{}) {
	helpers.ConfigureLogger(ctx, l.Logger).Infof(str, rest...)
}

func (l *GormLogger) Warn(ctx context.Context, str string, rest ...interface{}) {
	helpers.ConfigureLogger(ctx, l.Logger).Warnf(str, rest...)
}

func (l *GormLogger) Error(ctx context.Context, str string, rest ...interface{}) {
	helpers.ConfigureLogger(ctx, l.Logger).Errorf(str, rest...)
}

func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	le := helpers.ConfigureLogger(ctx, l.Logger)
	sql, rows := fc()
	if err != nil {
		le.Errorf("Took: %s, Err:%s, SQL: %s, AffectedRows: %d", time.Since(begin), err, sql, rows)
	} else {
		le.Tracef("Took: %s, SQL: %s, AffectedRows: %d", time.Since(begin), sql, rows)
	}
}
