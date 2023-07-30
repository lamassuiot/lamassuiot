package storage

import (
	"io"

	"github.com/sirupsen/logrus"
)

func NewStorageLogger(enable bool) *logrus.Entry {
	lStorage := logrus.WithField("subsystem", "Storage")
	if !enable {
		lStorage.Logger.SetOutput(io.Discard)
	}

	return lStorage
}
