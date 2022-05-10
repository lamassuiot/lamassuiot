package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	cloudproxyerrors "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/errors"
	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/store"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type DB struct {
	DB     *sql.DB
	logger log.Logger
}

func NewDB(db *sql.DB, logger log.Logger) store.DB {
	return &DB{DB: db, logger: logger}
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (db *DB) InsertSynchronizedCA(ctx context.Context, cloudConnectorID string, caName string, enabledTs time.Time) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	INSERT INTO synchronized_cas(connector_id, ca_name, serial_number, creation_ts)
	VALUES($1, $2, $3, $4);
	`
	span := opentracing.StartSpan("cloud-proxy: insert SynchronizedCA with CAName "+caName+" and ConnectorID"+cloudConnectorID+" in database", opentracing.ChildOf(parentSpan.Context()))
	_, err := db.DB.Exec(sqlStatement, cloudConnectorID, caName, "", enabledTs)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not insert SynchronizedCA with CAName "+caName+" and ConnectorID "+cloudConnectorID+" in database")

		switch e := err.(type) {
		case *pq.Error:
			if e.Code == "23505" {
				duplicationErr := &cloudproxyerrors.DuplicateResourceError{
					ResourceType: "SynchronizedCA",
					ResourceId:   caName + "-" + cloudConnectorID,
				}
				return duplicationErr
			} else {
				return e
			}
		default:
			return e
		}

	}
	return nil
}

func (db *DB) UpdateSynchronizedCA(ctx context.Context, cloudConnectorID string, caName string, serial_number string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE synchronized_cas
	SET serial_number = $1
	WHERE ca_name = $2 and connector_id = $3;
	`
	span := opentracing.StartSpan("cloud-proxy: update SynchronizedCA with CAName "+caName+" and ConnectorID"+cloudConnectorID+" in database", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.DB.Exec(sqlStatement, serial_number, caName, cloudConnectorID)
	span.Finish()

	if err != nil {
		level.Info(db.logger).Log("msg", "could no update SynchronizedCA with CAName "+caName+" and ConnectorID "+cloudConnectorID)
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		level.Info(db.logger).Log("msg", "could no update SynchronizedCA with CAName "+caName+" and ConnectorID "+cloudConnectorID)
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	return nil
}

func (db *DB) SelectAllSynchronizedCAs(ctx context.Context) ([]cloudproviders.DatabaseSynchronizedCA, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * 
	FROM synchronized_cas;
	`
	span := opentracing.StartSpan("cloud-proxy: obtain SynchronizedCA from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.DB.Query(sqlStatement)
	span.Finish()

	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain SynchronizedCA from database or the database is empty")
		return []cloudproviders.DatabaseSynchronizedCA{}, err
	}

	defer rows.Close()
	syncCAs := make([]cloudproviders.DatabaseSynchronizedCA, 0)

	for rows.Next() {
		var syncCA cloudproviders.DatabaseSynchronizedCA

		err := rows.Scan(&syncCA.CloudConnectorID, &syncCA.CAName, &syncCA.SerialNumber, &syncCA.EnabledTimestamp)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database SynchronizedCA row")
			return []cloudproviders.DatabaseSynchronizedCA{}, err
		}

		syncCAs = append(syncCAs, syncCA)
	}

	if err = rows.Err(); err != nil {
		level.Error(db.logger).Log("err", err)
		return []cloudproviders.DatabaseSynchronizedCA{}, err
	}

	return syncCAs, nil

}

func (db *DB) SelectSynchronizedCAsByCaName(ctx context.Context, caName string) ([]cloudproviders.DatabaseSynchronizedCA, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT *
	FROM synchronized_cas
	WHERE ca_name = $1;
	`
	span := opentracing.StartSpan("cloud-proxy: obtain SynchronizedCA by caName from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.DB.Query(sqlStatement, caName)
	span.Finish()

	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain SynchronizedCA from database or the database is empty")
		return []cloudproviders.DatabaseSynchronizedCA{}, err
	}

	defer rows.Close()
	syncCAs := make([]cloudproviders.DatabaseSynchronizedCA, 0)

	for rows.Next() {
		var syncCA cloudproviders.DatabaseSynchronizedCA

		err := rows.Scan(&syncCA.CloudConnectorID, &syncCA.CAName, &syncCA.SerialNumber, &syncCA.EnabledTimestamp)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database SynchronizedCA row")
			return []cloudproviders.DatabaseSynchronizedCA{}, err
		}

		syncCAs = append(syncCAs, syncCA)
	}

	if err = rows.Err(); err != nil {
		level.Error(db.logger).Log("err", err)
		return []cloudproviders.DatabaseSynchronizedCA{}, err
	}

	return syncCAs, nil

}

func (db *DB) SelectSynchronizedCAsByConnectorID(ctx context.Context, connectorID string) ([]cloudproviders.DatabaseSynchronizedCA, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT *
	FROM synchronized_cas
	WHERE connector_id = $1;
	`
	span := opentracing.StartSpan("cloud-proxy: obtain SynchronizedCA by connectorID from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.DB.Query(sqlStatement, connectorID)
	span.Finish()

	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain SynchronizedCA from database or the database is empty")
		return []cloudproviders.DatabaseSynchronizedCA{}, err
	}

	defer rows.Close()
	syncCAs := make([]cloudproviders.DatabaseSynchronizedCA, 0)

	for rows.Next() {
		var syncCA cloudproviders.DatabaseSynchronizedCA

		err := rows.Scan(&syncCA.CloudConnectorID, &syncCA.CAName, &syncCA.SerialNumber, &syncCA.EnabledTimestamp)
		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Unable to read database SynchronizedCA row")
			return []cloudproviders.DatabaseSynchronizedCA{}, err
		}

		syncCAs = append(syncCAs, syncCA)
	}

	if err = rows.Err(); err != nil {
		level.Error(db.logger).Log("err", err)
		return []cloudproviders.DatabaseSynchronizedCA{}, err
	}

	return syncCAs, nil

}

func (db *DB) SelectSynchronizedCAsByConnectorIDAndConnectorID(ctx context.Context, caName string, connectorID string) (cloudproviders.DatabaseSynchronizedCA, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT *
	FROM synchronized_cas
	WHERE ca_name = $1 and connector_id = $2;
	`
	span := opentracing.StartSpan("cloud-proxy: obtain SynchronizedCA by caName from database", opentracing.ChildOf(parentSpan.Context()))
	var syncCA cloudproviders.DatabaseSynchronizedCA
	err := db.DB.QueryRow(sqlStatement, caName, connectorID).Scan(
		&syncCA.CloudConnectorID, &syncCA.CAName, &syncCA.SerialNumber, &syncCA.EnabledTimestamp,
	)

	span.Finish()

	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain SynchronizedCA from database or the database is empty")
		return cloudproviders.DatabaseSynchronizedCA{}, err
	}

	return syncCA, nil
}
