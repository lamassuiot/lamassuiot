package mocks

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	//devicesStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/models/device/store"

	_ "github.com/lib/pq"
)

type caDBMock struct {
	*sql.DB
	logger log.Logger
}

func NewCasDBMock(t *testing.T) (*caDBMock, error) {
	t.Helper()
	db, err := sql.Open("driverName", "dataSourceName")

	if err != nil {
		return nil, err
	}
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	return &caDBMock{db, logger}, nil

}

func (db *caDBMock) InsertCert(ctx context.Context, caName string, serialNumber string) error {
	return nil

}

func (db *caDBMock) SelectCertsByCA(ctx context.Context, caName string, queryParameters filters.QueryParameters) ([]ca.IssuedCerts, int, error) {
	return []ca.IssuedCerts{}, 0, nil
}
