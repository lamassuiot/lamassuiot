package db

/*import (
	"context"
	"database/sql"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassu-enroller/pkg/devices/server/models/device/store"
	"github.com/opentracing/opentracing-go"

	_ "github.com/lib/pq"
)

func NewDB(driverName string, dataSourceName string, logger log.Logger) (store.DB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	err = checkDBAlive(db)
	for err != nil {
		level.Warn(logger).Log("msg", "Trying to connect to Device DB")
		err = checkDBAlive(db)
	}

	return &DB{db, logger}, nil
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

type DB struct {
	*sql.DB
	logger log.Logger
}

func (db *DB) CountDevicesByDmsId(ctx context.Context, dmsId string) (int, error) {
	parentSpan := opentracing.SpanFromContext(ctx)
	span := opentracing.StartSpan("lamassu-device-manager: Count Device Device by Dms_Id from database", opentracing.ChildOf(parentSpan.Context()))
	//Get Enrolled_Devices per dms_id
	var length int
	sqlStatement1 := `
	SELECT COUNT(*) as count FROM device_information where dms_id = $1 and status <> 'PENDING_PROVISION'
	`
	//Count all devices which have status != PENDING_PROVISION
	err := db.QueryRow(sqlStatement1, dmsId).Scan(&length)

	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Device "+dmsId+" from database")
		return 0, err
	}

	return length, err
}
*/
