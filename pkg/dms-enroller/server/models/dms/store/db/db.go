package db

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	dmserrors "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms/store"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/opentracing/opentracing-go"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	_ "github.com/lib/pq"
)

func NewDB(db *sql.DB, logger log.Logger) store.DB {
	return &DB{db, logger}
}

type DB struct {
	*sql.DB
	logger log.Logger
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (db *DB) Insert(ctx context.Context, d dto.DMS) (string, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	var id string
	sqlStatement := `
	INSERT INTO dms_store(id,name, serialNumber, keyType, keyBits, csrBase64, status, creation_ts, modification_ts)
	VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
	RETURNING id;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: insert DMS with name "+d.Name+" in database", opentracing.ChildOf(parentSpan.Context()))
	err := db.QueryRow(sqlStatement, d.Id, d.Name, d.SerialNumber, d.KeyMetadata.KeyType, d.KeyMetadata.KeyBits, d.CsrBase64, d.Status, time.Now(), time.Now()).Scan(&id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not insert DMS with name "+d.Name+" in database")
		duplicationErr := &dmserrors.DuplicateResourceError{
			ResourceType: "DMS",
			ResourceId:   id,
		}
		return "", duplicationErr
	}
	level.Debug(db.logger).Log("msg", "DMS with ID "+id+" inserted in database")
	return id, nil
}

func (db *DB) SelectAll(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMS, int, error) {
	var length int
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `SELECT COUNT(*) as count FROM dms_store  `
	rows, err := db.Query(sqlStatement)
	if err != nil {
		return []dto.DMS{}, 0, err
	}
	rows.Next()
	err = rows.Scan(&length)
	if err != nil {
		return []dto.DMS{}, 0, err
	}
	rows.Close()
	sqlStatement = `
	SELECT * FROM dms_store
	`
	sqlStatement = filters.ApplySQLFilter(sqlStatement, queryParameters)
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain DMSs from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err = db.Query(sqlStatement)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain DMSs from database or the database is empty")
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   "Database is empty",
		}
		return []dto.DMS{}, 0, notFoundErr
	}
	defer rows.Close()
	dmss := make([]dto.DMS, 0)

	for rows.Next() {
		var d dto.DMS
		err := rows.Scan(&d.Id, &d.Name, &d.SerialNumber, &d.KeyMetadata.KeyType, &d.KeyMetadata.KeyBits, &d.CsrBase64, &d.Status, &d.CreationTimestamp, &d.ModificationTimestamp)
		if err != nil {
			return []dto.DMS{}, 0, err
		}
		d.KeyMetadata.KeyStrength = getKeyStrength(d.KeyMetadata.KeyType, d.KeyMetadata.KeyBits)
		span.Finish()
		dmss = append(dmss, d)
	}
	if err = rows.Err(); err != nil {
		level.Debug(db.logger).Log("err", err)
		return []dto.DMS{}, 0, err
	}
	level.Debug(db.logger).Log("msg", strconv.Itoa(len(dmss))+" DMSs read from database")
	return dmss, length, nil
}

func (db *DB) SelectByID(ctx context.Context, id string) (dto.DMS, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT *
	FROM dms_store
	WHERE id = $1;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain DMS with ID "+id+" from database", opentracing.ChildOf(parentSpan.Context()))
	row := db.QueryRow(sqlStatement, id)
	var d dto.DMS
	err := row.Scan(&d.Id, &d.Name, &d.SerialNumber, &d.KeyMetadata.KeyType, &d.KeyMetadata.KeyBits, &d.CsrBase64, &d.Status, &d.CreationTimestamp, &d.ModificationTimestamp)
	if err != nil {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   id,
		}
		return dto.DMS{}, notFoundErr
	}
	span.Finish()
	d.KeyMetadata.KeyStrength = getKeyStrength(d.KeyMetadata.KeyType, d.KeyMetadata.KeyBits)

	level.Debug(db.logger).Log("msg", "DMS with ID "+id+" obtained from database")
	return d, nil
}

func (db *DB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT *
	FROM dms_store
	WHERE serialNumber = $1;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain DMS with SerialNumber "+SerialNumber+" from database", opentracing.ChildOf(parentSpan.Context()))
	row, err := db.Query(sqlStatement, SerialNumber)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain DMS")
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   SerialNumber,
		}
		return "", notFoundErr
	}
	span.Finish()
	defer row.Close()
	var d dto.DMS
	for row.Next() {

		err = row.Scan(&d.Id, &d.Name, &d.SerialNumber, &d.KeyMetadata.KeyType, &d.KeyMetadata.KeyBits, &d.CsrBase64, &d.Status, &d.CreationTimestamp, &d.ModificationTimestamp)
		if err != nil {
			return "", err
		}
	}
	return d.Id, nil
}

func (db *DB) UpdateByID(ctx context.Context, id string, status string, serialNumber string, encodedCsr string) (dto.DMS, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE dms_store
	SET status = $1, serialNumber = $2, csrBase64 = $3, modification_ts = $4
	WHERE id = $5;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: update DMS with ID "+id+" status to "+status, opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, status, serialNumber, encodedCsr, time.Now(), id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not update DMS with ID "+id+" status to "+status)
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   id,
		}
		return dto.DMS{}, notFoundErr
	}
	count, err := res.RowsAffected()
	if err != nil {
		return dto.DMS{}, err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Debug(db.logger).Log("err", err)
		return dto.DMS{}, err
	}
	level.Debug(db.logger).Log("msg", "DMS with ID "+id+" status updated to"+status)
	return db.SelectByID(ctx, id)
}

func (db *DB) Delete(ctx context.Context, id string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	DELETE FROM dms_store
	WHERE id = $1;
	`
	span := opentracing.StartSpan("delete DMS with ID "+id+" from database", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not delete DMS with ID "+id+" from database")
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   id,
		}
		return notFoundErr
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count <= 0 {
		err = errors.New("no rows have been updated in database")
		level.Debug(db.logger).Log("err", err)
		return err
	}
	return nil
}

func (db *DB) InsertAuthorizedCAs(ctx context.Context, dmsid string, CAs []string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	for i := 0; i < len(CAs); i++ {
		sqlStatement := `
		INSERT INTO authorized_cas(dmsid,caname)
		VALUES($1,$2)
		RETURNING dmsid;
		`
		span := opentracing.StartSpan("lamassu-dms-enroller: insert Authorized CA with name "+CAs[i]+" in authorized_cas database", opentracing.ChildOf(parentSpan.Context()))
		err := db.QueryRow(sqlStatement, dmsid, CAs[i]).Scan(&dmsid)
		span.Finish()
		if err != nil {
			level.Debug(db.logger).Log("err", err, "msg", "Could not insert CA with name "+CAs[i]+" in authorized_cas database")
			duplicationErr := &dmserrors.DuplicateResourceError{
				ResourceType: "DMS",
				ResourceId:   dmsid,
			}
			return duplicationErr
		}
	}
	level.Debug(db.logger).Log("msg", "DMS with ID "+dmsid+" inserted in authorized_cas database")
	return nil
}
func (db *DB) DeleteAuthorizedCAs(ctx context.Context, dmsid string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	DELETE FROM authorized_cas
	WHERE dmsid = $1;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: delete DMS with ID "+dmsid+" from authorized_cas database", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, dmsid)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not delete DMS with ID "+dmsid+" in authorized_cas database")
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count <= 0 {
		err = errors.New("no rows have been updated in database")
		level.Debug(db.logger).Log("err", err)
		return err
	}
	level.Debug(db.logger).Log("msg", "DMS with ID "+dmsid+" deleted in authorized_cas database")
	return nil
}

func (db *DB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * 
	FROM authorized_cas
	WHERE dmsid = $1;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain Authorized CAs with DMS ID"+dmsid+"from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, dmsid)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain DMSs from database or the database is empty")
		return nil, err
	}
	defer rows.Close()
	cass := make([]dms.AuthorizedCAs, 0)

	for rows.Next() {
		var d dms.AuthorizedCAs
		err := rows.Scan(&d.DmsId, &d.CaName)
		if err != nil {
			return nil, err
		}
		cass = append(cass, d)
	}
	if err = rows.Err(); err != nil {
		level.Debug(db.logger).Log("err", err)
		return nil, err
	}
	return cass, nil
}
func (db *DB) SelectAllAuthorizedCAs(ctx context.Context) ([]dms.AuthorizedCAs, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * 
	FROM authorized_cas;
	`
	span := opentracing.StartSpan("lamassu-dms-enroller: obtain authorized CAs from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain authorized CAs from database or the database is empty")
		return []dms.AuthorizedCAs{}, err
	}
	defer rows.Close()
	dmss := make([]dms.AuthorizedCAs, 0)

	for rows.Next() {
		var d dms.AuthorizedCAs
		err := rows.Scan(&d.DmsId, &d.CaName)
		if err != nil {
			return []dms.AuthorizedCAs{}, err
		}
		dmss = append(dmss, d)
	}
	if err = rows.Err(); err != nil {
		level.Debug(db.logger).Log("err", err)
		return []dms.AuthorizedCAs{}, err
	}
	level.Debug(db.logger).Log("msg", strconv.Itoa(len(dmss))+" DMSs read from database")

	return dmss, nil
}

func (db *DB) CountEnrolledDevices(ctx context.Context, dms_id string) (int, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	var length int
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement1 := `
		SELECT COUNT(*) as count FROM device_information where dms_id = $1 and status <> $2
		`
	span := opentracing.StartSpan("lamassu-device-manager: Count Devices by DMS "+dms_id+" from database", opentracing.ChildOf(parentSpan.Context()))

	err := db.QueryRow(sqlStatement1, dms_id, "PENDING_PROVISION").Scan(
		&length,
	)

	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Device "+dms_id+" from database")
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   dms_id,
		}
		return 0, notFoundErr
	}

	return length, nil

}

func getKeyStrength(keyType string, keyBits int) string {
	var keyStrength string = "unknown"
	switch keyType {
	case "RSA":
		if keyBits < 2048 {
			keyStrength = "low"
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "EC":
		if keyBits < 224 {
			keyStrength = "low"
		} else if keyBits >= 224 && keyBits < 256 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	}
	return keyStrength
}
