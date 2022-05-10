package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	devmanagererrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"

	_ "github.com/lib/pq"
)

func NewDB(db *sql.DB, logger log.Logger) (store.DB, error) {
	return &DB{db, logger}, nil
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

func (db *DB) InsertDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	sqlStatement := `
	INSERT INTO devices(id, alias,description,tags, icon_name, icon_color, status, dms_id,country, state ,locality ,organization ,organization_unit, common_name, key_type, key_bits, key_strength, current_cert_serial_number, creation_ts, modification_ts)
	VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	RETURNING id;
	`
	var id string
	span := opentracing.StartSpan("lamassu-device-manager: Insert Device with ID "+id+" in database", opentracing.ChildOf(parentSpan.Context()))

	err := db.QueryRow(sqlStatement,
		deviceID,
		alias,
		description,
		pq.Array(tags),
		iconName,
		iconColor,
		device.DevicePendingProvision,
		dmsID,
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		0,
		"",
		"",
		time.Now(),
		time.Now(),
	).Scan(&id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not insert device with ID "+deviceID+" in database")
		duplicationErr := &devmanagererrors.DuplicateResourceError{
			ResourceType: "DEVICE",
			ResourceId:   deviceID,
		}
		return duplicationErr
	}
	level.Debug(db.logger).Log("msg", "Device with ID "+id+" inserted in database")
	return nil
}

func (db *DB) SelectAllDevices(ctx context.Context, queryParameters dto.QueryParameters) ([]dto.Device, int, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	var length int
	sqlStatement1 := `SELECT COUNT(*) as count FROM devices  `
	rows, err := db.Query(sqlStatement1)
	if err != nil {
		return []dto.Device{}, 0, err
	}
	rows.Next()
	err = rows.Scan(&length)
	if err != nil {
		return []dto.Device{}, 0, err
	}
	rows.Close()
	sqlStatement := `SELECT * FROM devices  `
	sqlStatement = applyFilter(sqlStatement, queryParameters)

	span := opentracing.StartSpan("lamassu-device-manager: Select All Devices from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err = db.Query(sqlStatement)

	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Devices from database")
		return []dto.Device{}, 0, err
	}
	defer rows.Close()

	devices := make([]dto.Device, 0)
	for rows.Next() {
		var dev dto.Device
		err := rows.Scan(&dev.Id, &dev.Alias, &dev.Description, pq.Array(&dev.Tags), &dev.IconName, &dev.IconColor, &dev.Status, &dev.DmsId, &dev.Subject.C, &dev.Subject.ST, &dev.Subject.L, &dev.Subject.O, &dev.Subject.OU, &dev.Subject.CN, &dev.KeyMetadata.KeyStrength, &dev.KeyMetadata.KeyType, &dev.KeyMetadata.KeyBits, &dev.CreationTimestamp, &dev.ModificationTimestamp, &dev.CurrentCertificate.SerialNumber)
		if err != nil {
			return []dto.Device{}, 0, err
		}

		devices = append(devices, dev)
	}

	return devices, length, nil
}

func (db *DB) SelectDeviceById(ctx context.Context, id string) (dto.Device, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM devices where id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Select Device by ID "+id+" from database", opentracing.ChildOf(parentSpan.Context()))
	var dev dto.Device
	err := db.QueryRow(sqlStatement, id).Scan(
		&dev.Id, &dev.Alias, &dev.Description, pq.Array(&dev.Tags), &dev.IconName, &dev.IconColor, &dev.Status, &dev.DmsId, &dev.Subject.C, &dev.Subject.ST, &dev.Subject.L, &dev.Subject.O, &dev.Subject.OU, &dev.Subject.CN, &dev.KeyMetadata.KeyStrength, &dev.KeyMetadata.KeyType, &dev.KeyMetadata.KeyBits, &dev.CreationTimestamp, &dev.ModificationTimestamp, &dev.CurrentCertificate.SerialNumber,
	)

	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Device "+id+" from database")
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE",
			ResourceId:   id,
		}
		return dto.Device{}, notFoundErr
	}

	return dev, nil
}

func (db *DB) UpdateByID(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE devices
	SET alias = $1, dms_id = $2, description = $3, tags=$4, icon_name=$5, icon_color=$6
	WHERE id = $7;
	`
	span := opentracing.StartSpan("lamassu-device-manager: update Device with ID "+deviceID, opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, alias, dmsID, description, pq.Array(tags), iconName, iconColor, deviceID)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not update Device with ID "+deviceID)
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	level.Debug(db.logger).Log("msg", "Device with ID "+deviceID+" updated")
	return nil

}
func (db *DB) SetKeyAndSubject(ctx context.Context, keyMetadate dto.PrivateKeyMetadataWithStregth, subject dto.Subject, deviceId string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE devices
	SET country = $1, state = $2, locality = $3, organization=$4, organization_unit=$5, common_name=$6, key_strength=$7, key_type=$8, key_bits=$9
	WHERE id = $10;
	`
	span := opentracing.StartSpan("lamassu-device-manager: update Device with ID "+deviceId, opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, subject.C, subject.ST, subject.L, subject.O, subject.OU, subject.CN, keyMetadate.KeyStrength, keyMetadate.KeyType, keyMetadate.KeyBits, deviceId)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not update Device with ID "+deviceId)
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(db.logger).Log("err", err)
		return err
	}
	level.Debug(db.logger).Log("msg", "Device with ID "+deviceId+" updated")
	return nil

}
func (db *DB) SelectAllDevicesByDmsId(ctx context.Context, dms_id string, queryParameters dto.QueryParameters) ([]dto.Device, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	sqlStatement := `
	SELECT * FROM devices where dms_id = $1
	`
	sqlStatement = applyFilter(sqlStatement, queryParameters)

	span := opentracing.StartSpan("lamassu-device-manager: Select All Devices by DMS ID from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, dms_id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Devices from database")
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE",
			ResourceId:   dms_id,
		}
		return []dto.Device{}, notFoundErr
	}
	defer rows.Close()

	var devices []dto.Device
	for rows.Next() {
		var dev dto.Device
		err := rows.Scan(&dev.Id, &dev.Alias, &dev.Description, pq.Array(&dev.Tags), &dev.IconName, &dev.IconColor, &dev.Status, &dev.DmsId, &dev.Subject.C, &dev.Subject.ST, &dev.Subject.L, &dev.Subject.O, &dev.Subject.OU, &dev.Subject.CN, &dev.KeyMetadata.KeyStrength, &dev.KeyMetadata.KeyType, &dev.KeyMetadata.KeyBits, &dev.CreationTimestamp, &dev.ModificationTimestamp, &dev.CurrentCertificate.SerialNumber)
		if err != nil {
			return []dto.Device{}, err
		}
		devices = append(devices, dev)
	}

	return devices, nil
}

func (db *DB) UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE devices
	SET status = $2, modification_ts=$3
	WHERE id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Update Device with ID "+id+" to "+newStatus+" status", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id, newStatus, time.Now())
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not updated Device with ID "+id+" to "+newStatus+" status")
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
	level.Debug(db.logger).Log("msg", "Updated device with ID "+id+" to "+newStatus+" status")
	return nil
}

func (db *DB) UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	UPDATE devices 
	SET current_cert_serial_number = $2 
	WHERE id = $1
	`
	span := opentracing.StartSpan("lamassu-device-manager: Update Devices Certificate  with ID "+id+" to "+serialNumber+" serial number", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id, serialNumber)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not updated Device with ID "+id+" to "+serialNumber+" serial number")
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
	level.Debug(db.logger).Log("err", err, "msg", "Updated device with ID "+id+" to "+serialNumber+" serial number")
	return nil
}

func (db *DB) DeleteDevice(ctx context.Context, id string) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	DELETE FROM devices
	WHERE id = $1;
	`
	span := opentracing.StartSpan("lamassu-device-manager: Delete device with ID "+id+" from database", opentracing.ChildOf(parentSpan.Context()))
	res, err := db.Exec(sqlStatement, id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not delete Device with ID "+id+" from database")
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
	return nil
}

func (db *DB) InsertLog(ctx context.Context, logDev dto.DeviceLog) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	INSERT INTO device_logs(id, creation_ts, device_uuid, log_type,log_message)
	VALUES($1, $2, $3, $4, $5)
	RETURNING id;
	`
	span := opentracing.StartSpan("lamassu-device-manager:  insert Log Device for device with ID "+logDev.DeviceId+" in database", opentracing.ChildOf(parentSpan.Context()))
	var id = uuid.NewString()
	err := db.QueryRow(sqlStatement,
		id,
		time.Now(),
		logDev.DeviceId,
		logDev.LogType,
		logDev.LogMessage,
	).Scan(&logDev.Id)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not insert Log Device for device with ID "+logDev.DeviceId+" in database")
		return err
	}
	level.Debug(db.logger).Log("msg", "Device Log with ID "+id+" inserted in database")
	return nil
}
func (db *DB) SelectDeviceLogs(ctx context.Context, deviceId string) ([]dto.DeviceLog, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_logs WHERE device_uuid = $1
	`

	span := opentracing.StartSpan("lamassu-device-manager: Select Devoces Logs from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, deviceId)
	span.Finish()
	if err != nil {
		level.Error(db.logger).Log("err", err, "msg", "Could not obtain Devices Logs from database")
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE-LOGS",
			ResourceId:   deviceId,
		}
		return []dto.DeviceLog{}, notFoundErr
	}
	defer rows.Close()

	var deviceLogs []dto.DeviceLog
	for rows.Next() {
		var log dto.DeviceLog
		err := rows.Scan(&log.Id, &log.Timestamp, &log.DeviceId, &log.LogType, &log.LogMessage)
		if err != nil {
			return []dto.DeviceLog{}, err
		}
		level.Debug(db.logger).Log("msg", "DeviceLog with ID "+log.Id+" read from database")
		deviceLogs = append(deviceLogs, log)
	}

	return deviceLogs, err
}

func (db *DB) InsertDeviceCertHistory(ctx context.Context, certHistory dto.DeviceCertHistory) error {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	INSERT INTO device_certificates_history(serial_number, device_uuid, issuer_name, creation_ts)
	VALUES($1, $2, $3, $4)
	`

	span := opentracing.StartSpan("lamassu-device-manager:insert Devices Cert History for device with SerialNumber "+certHistory.SerialNumber+" in database", opentracing.ChildOf(parentSpan.Context()))
	_, err := db.Exec(sqlStatement,
		certHistory.SerialNumber,
		certHistory.DeviceId,
		certHistory.IsuuerName,
		time.Now(),
	)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not insert Devices Cert History for device with SerialNumber "+certHistory.SerialNumber+" in database")
		return err
	}
	level.Debug(db.logger).Log("msg", "Devices Cert History with Serial Number "+certHistory.SerialNumber+" inserted in database")
	return nil
}

func (db *DB) SelectDeviceCertHistory(ctx context.Context, deviceId string) ([]dto.DeviceCertHistory, error) {

	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	sqlStatement := `
	SELECT * FROM device_certificates_history WHERE device_uuid = $1
	`

	span := opentracing.StartSpan("lamassu-device-manager: Select Devices Cert History from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement, deviceId)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Devices Cert History from database")
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE-CERT HISTORY",
			ResourceId:   deviceId,
		}

		return []dto.DeviceCertHistory{}, notFoundErr
	}
	defer rows.Close()

	var deviceCertHistory = []dto.DeviceCertHistory{}
	for rows.Next() {
		var certHistory dto.DeviceCertHistory
		err := rows.Scan(&certHistory.SerialNumber, &certHistory.DeviceId, &certHistory.IsuuerName, &certHistory.CreationTimestamp)

		if err != nil {
			return []dto.DeviceCertHistory{}, err
		}
		level.Debug(db.logger).Log("msg", "Devices Cert History with SerialNumber "+certHistory.SerialNumber+" read from database")
		deviceCertHistory = append(deviceCertHistory, certHistory)
	}
	return deviceCertHistory, nil
}

func (db *DB) SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (dto.DeviceCertHistory, error) {

	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM device_certificates_history WHERE serial_number = $1
	`
	var devCh dto.DeviceCertHistory
	span := opentracing.StartSpan("lamassu-device-manager: Select Device Device Cert history with serialNumber: "+serialNumber+" from database", opentracing.ChildOf(parentSpan.Context()))
	err := db.QueryRow(sqlStatement, serialNumber).Scan(
		&devCh.SerialNumber, &devCh.DeviceId, &devCh.IsuuerName, &devCh.CreationTimestamp,
	)
	span.Finish()

	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Device Cert history with serialNumber: "+serialNumber+" from database")
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE-CERT HISTORY",
			ResourceId:   serialNumber,
		}
		return dto.DeviceCertHistory{}, notFoundErr
	}

	return devCh, nil
}
func (db *DB) SelectDeviceCertHistoryLastThirtyDays(ctx context.Context, queryParameters dto.QueryParameters) ([]dto.DeviceCertHistory, error) {

	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)

	sqlStatement := `
	SELECT * FROM device_certificates_history WHERE creation_ts >= NOW() - INTERVAL '30 days'
	`
	sqlStatement = applyFilter(sqlStatement, queryParameters)
	span := opentracing.StartSpan("lamassu-device-manager: Select Device Device Cert history Last Thirty Days from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Devices Cert History from database")
		return []dto.DeviceCertHistory{}, err
	}
	defer rows.Close()

	var deviceCertHistory = []dto.DeviceCertHistory{}
	for rows.Next() {
		var certHistory dto.DeviceCertHistory
		err := rows.Scan(&certHistory.SerialNumber, &certHistory.DeviceId, &certHistory.IsuuerName, &certHistory.CreationTimestamp)
		if err != nil {
			return []dto.DeviceCertHistory{}, err
		}
		deviceCertHistory = append(deviceCertHistory, certHistory)
	}

	return deviceCertHistory, nil
}
func (db *DB) SelectDmssLastIssuedCert(ctx context.Context, queryParameters dto.QueryParameters) ([]dto.DMSLastIssued, error) {
	db.logger = ctx.Value(utils.LamassuLoggerContextKey).(log.Logger)
	parentSpan := opentracing.SpanFromContext(ctx)
	sqlStatement := `
	SELECT * FROM last_issued_cert_by_dms
	`
	sqlStatement = applyFilter(sqlStatement, queryParameters)
	span := opentracing.StartSpan("lamassu-device-manager: Select Last Issued Cert By DMS from database", opentracing.ChildOf(parentSpan.Context()))
	rows, err := db.Query(sqlStatement)
	span.Finish()
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Last Issued Cert By DMS from database")
		return []dto.DMSLastIssued{}, err
	}
	defer rows.Close()

	var dmssLastIssued = []dto.DMSLastIssued{}
	for rows.Next() {
		var lastIssued dto.DMSLastIssued
		err := rows.Scan(&lastIssued.DmsId, &lastIssued.Timestamp, &lastIssued.SerialNumber)
		if err != nil {
			return []dto.DMSLastIssued{}, err
		}
		dmssLastIssued = append(dmssLastIssued, lastIssued)
	}

	return dmssLastIssued, nil
}
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func applyFilter(sqlStatement string, queryParameters dto.QueryParameters) string {
	fields := []string{"id", "alias", "description", "status", "dms_id", "key_strength", "tags", "creation_ts"} //Switch Case por fields en lugar de tipo de dato
	fmt.Printf("fields: %v\n", fields)
	bigOperator := " AND "
	helper := queryParameters.Filter
	if queryParameters.Filter != "" {
		if !strings.Contains(sqlStatement, "WHERE") {
			sqlStatement = sqlStatement + " WHERE 1=1 "
		}
		for len(helper) > 0 {

			if !strings.HasPrefix(helper, ")") {
				if strings.HasPrefix(helper, ",") {
					helper = strings.TrimPrefix(helper, ",")
				}
				if strings.HasPrefix(helper, "and") {
					helper = strings.TrimPrefix(helper, "and(")
					bigOperator = " AND "
				}
				if strings.HasPrefix(helper, "or") {
					helper = strings.TrimPrefix(helper, "or(")
					bigOperator = " OR "
				}

				if strings.HasPrefix(helper, " ") {
					helper = strings.TrimPrefix(helper, " ")
				}
				operator := helper[:strings.IndexByte(helper, '(')]
				var rgx = regexp.MustCompile(`\((.*?)\)`)
				arguments := rgx.FindStringSubmatch(helper)
				split := strings.Split(arguments[1], ",")
				field := split[0]
				var data string
				data = split[1]

				if contains(fields, field) {
					switch field {
					/*	case "INTEGER COLUMN":
						_, err := strconv.Atoi(data)
						if err == nil {
							switch operator {
							case "eq":
								sqlStatement = sqlStatement + bigOperator + field + "= '" + data + "' "
							case "nq":
								sqlStatement = sqlStatement + bigOperator + field + "<> '" + data + "' "
							case "lt":
								sqlStatement = sqlStatement + bigOperator + field + "< '" + data + "' "
							case "le":
								sqlStatement = sqlStatement + bigOperator + field + "<= '" + data + "' "
							case "gt":
								sqlStatement = sqlStatement + bigOperator + field + "> '" + data + "' "
							case "ge":
								sqlStatement = sqlStatement + bigOperator + field + ">= '" + data + "' "
							default:
							}
						}
					*/
					case "creation_ts":

						_, err := time.Parse("2006-01-02", data)
						if err == nil {
							switch operator {
							case "eq":
								sqlStatement = sqlStatement + bigOperator + field + "= '" + data + "' "
							case "nq":
								sqlStatement = sqlStatement + bigOperator + field + "<> '" + data + "' "
							case "lt":
								sqlStatement = sqlStatement + bigOperator + field + "< '" + data + "' "
							case "le":
								sqlStatement = sqlStatement + bigOperator + field + "<= '" + data + "' "
							case "gt":
								sqlStatement = sqlStatement + bigOperator + field + "> '" + data + "' "
							case "ge":
								sqlStatement = sqlStatement + bigOperator + field + ">= '" + data + "' "
							default:
								return sqlStatement
							}
						}

					case "key_strength":
						keyStrength := []string{"low", "medium", "high"}
						if contains(keyStrength, data) {
							switch operator {
							case "eq":
								sqlStatement = sqlStatement + bigOperator + field + "= '" + data + "' "
							case "contains":
								sqlStatement = sqlStatement + bigOperator + field + " LIKE  '%" + data + "%' "
							default:
								return sqlStatement
							}

						}

					case "status":
						status := []string{device.DevicePendingProvision.String(),
							device.DeviceProvisioned.String(),
							device.DeviceCertRevoked.String(),
							device.DeviceCertExpired.String(),
							device.DeviceDecommisioned.String()}

						if contains(status, data) {
							switch operator {
							case "eq":
								sqlStatement = sqlStatement + bigOperator + field + "= '" + data + "' "
							case "contains":
								sqlStatement = sqlStatement + bigOperator + field + " LIKE  '%" + data + "%' "
							default:
								return sqlStatement
							}

						}

					case "tags":
						if operator == "contains" {
							sqlStatement = sqlStatement + bigOperator + field + " IN (" + data + ") "
						} else {
							return sqlStatement
						}

					default:
						switch operator {
						case "eq":
							sqlStatement = sqlStatement + bigOperator + field + "= '" + data + "' "
						case "contains":
							sqlStatement = sqlStatement + bigOperator + field + " LIKE  '%" + data + "%' "
						default:
							return sqlStatement
						}

					}

					toRemove := helper[:len(operator)+len(arguments[0])]
					helper = strings.TrimPrefix(helper, toRemove)
				}
			} else {
				if strings.HasPrefix(helper, ")") {
					helper = strings.TrimPrefix(helper, ")")
				}
				if strings.HasPrefix(helper, " ") {
					helper = strings.TrimPrefix(helper, " ")
				}
				if strings.HasPrefix(helper, ",") {
					helper = strings.TrimPrefix(helper, ",")
				}

			}

		}

	}
	if queryParameters.Order.Order != "" {
		if strings.ToUpper(queryParameters.Order.Order) == "ASC" || strings.ToUpper(queryParameters.Order.Order) == "DESC" {
			sqlStatement = sqlStatement + "ORDER BY " + queryParameters.Order.Field + " " + strings.ToUpper(queryParameters.Order.Order)
		}
	}
	if queryParameters.Pagination.Page != 0 {
		perPage := 100
		if queryParameters.Pagination.Offset > 0 {
			perPage = queryParameters.Pagination.Offset
		}
		sqlStatement = sqlStatement + " OFFSET " + strconv.Itoa(((queryParameters.Pagination.Page - 1) * perPage)) + " ROWS FETCH NEXT " + strconv.Itoa(perPage) + " ROWS ONLY"
	}
	return sqlStatement
}
