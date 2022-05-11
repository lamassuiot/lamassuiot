package mocks

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
)

func NewDmsDBMock(t *testing.T) (*DmsDB, error) {
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

	return &DmsDB{db, logger}, nil

}

type DmsDB struct {
	*sql.DB
	logger log.Logger
}

func (db *DmsDB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {

	return "810fbd45-55a6-4dd7-8466-c3d3eb854357", nil
}
func (db *DmsDB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	authCA := dms.AuthorizedCAs{
		DmsId:  "810fbd45-55a6-4dd7-8466-c3d3eb854357",
		CaName: "IkerCA",
	}
	var list []dms.AuthorizedCAs
	list = append(list, authCA)
	return list, nil
}
