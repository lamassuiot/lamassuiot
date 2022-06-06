package mocks

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	devmanagererrors "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/errors"
	_ "github.com/lib/pq"
)

var (
	// Client errors
	ErrInvalidDeviceRequest = errors.New("unable to parse device, is invalid")    //400
	ErrInvalidDMSId         = errors.New("unable to parse DMS ID, is invalid")    //400
	ErrInvalidDeviceId      = errors.New("unable to parse Device ID, is invalid") //400
	ErrIncorrectType        = errors.New("unsupported media type")                //415
	ErrEmptyBody            = errors.New("empty body")

	//Server errors
	ErrInvalidOperation = errors.New("invalid operation")
	ErrActiveCert       = errors.New("can't isuee certificate. The device has a valid cert")
	ErrResponseEncode   = errors.New("error encoding response")
	ErrInsertLog        = errors.New("Could not insert log")
	ErrInsertDevice     = errors.New("Could not insert device")
	ErrDeviceById       = errors.New("Could not find device by Id")
	ErrSerialNumber     = errors.New("No Serial Number")
)
var device = testDevice()

type MockDB struct {
	*sql.DB
	logger log.Logger
}

func NewDevicedDBMock(t *testing.T) (*MockDB, error) {
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

	return &MockDB{db, logger}, nil

}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (db *MockDB) GetStats(ctx context.Context) (dto.Stats, time.Time) {
	stat := dto.Stats{
		PendingEnrollment: 1,
		Provisioned:       0,
		Decomissioned:     0,
		AboutToExpire:     5,
		Expired:           1,
		Revoked:           2,
	}
	return stat, time.Now()
}
func (db *MockDB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {

	return "810fbd45-55a6-4dd7-8466-c3d3eb854357", nil

}
func (db *MockDB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	var cas []dms.AuthorizedCAs
	ca := dms.AuthorizedCAs{
		CaName: "Lamassu DMS Enroller",
		DmsId:  "810fbd45-55a6-4dd7-8466-c3d3eb854357",
	}
	cas = append(cas, ca)

	return cas, nil
}
func (db *MockDB) UpdateByID(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error {
	if deviceID == "error" {
		return errors.New("No rows have been updated in database")
	} else {
		return nil
	}
}

func (db *MockDB) InsertDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error {

	if deviceID == device.Id {
		duplicationErr := &devmanagererrors.DuplicateResourceError{
			ResourceType: "DEVICE",
			ResourceId:   deviceID,
		}
		return duplicationErr
	} else {
		return nil
	}
}

func (db *MockDB) SelectDeviceById(ctx context.Context, id string) (dto.Device, error) {
	dev := testDevice()
	devNoSerialNumber := testDeviceNoSerialNumber()
	dev.Id = "2"
	if ctx.Value("DBSelectDeviceById") != nil {
		failDBLog := ctx.Value("DBSelectDeviceById").(bool)
		if id == "noSerialNumber" {
			return devNoSerialNumber, nil
		}
		if failDBLog {
			notFoundErr := &devmanagererrors.ResourceNotFoundError{
				ResourceType: "DEVICE",
				ResourceId:   id,
			}
			return dto.Device{}, notFoundErr
		}
	}

	if id == "DEVICE" {
		dev.Status = "DEVICE_PROVISIONED"
		return dev, nil
	} else if id != device.Id && id != dev.Id {
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE",
			ResourceId:   id,
		}
		return dto.Device{}, notFoundErr
	} else {
		return dev, nil
	}
}

func (db *MockDB) SelectAllDevices(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.Device, int, error) {
	if ctx.Value("DBShouldFail") != nil {
		failDB := ctx.Value("DBShouldFail").(bool)

		if failDB {
			var a []dto.Device
			return a, 0, errors.New("Testing DB connection failed")
		} else {
			var devList []dto.Device
			var d dto.Device
			var noSerialNumber dto.Device
			d = testDevice()
			noSerialNumber = testDevice()
			noSerialNumber.CurrentCertificate.SerialNumber = ""
			devList = append(devList, d)
			devList = append(devList, noSerialNumber)
			return devList, 0, nil
		}
	} else {
		var devList []dto.Device
		var d dto.Device
		d = testDevice()
		devList = append(devList, d)
		return devList, 0, nil
	}
}
func (db *MockDB) SelectAllDevicesByDmsId(ctx context.Context, dms_id string, queryParameters filters.QueryParameters) ([]dto.Device, error) {
	var devList []dto.Device
	var d dto.Device
	var dNoSerialNumber dto.Device
	d = testDevice()
	dNoSerialNumber = testDevice()
	dNoSerialNumber.Id = "dNoSerialNumber"
	dNoSerialNumber.CurrentCertificate.SerialNumber = ""

	devList = append(devList, d)
	devList = append(devList, dNoSerialNumber)

	if dms_id == "error" {
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE",
			ResourceId:   dms_id,
		}
		return []dto.Device{}, notFoundErr
	}
	return devList, nil
}

func (db *MockDB) UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error {
	if ctx.Value("DBUpdateDeviceCertificateSerialNumberByID") != nil {
		failDBLog := ctx.Value("DBUpdateDeviceCertificateSerialNumberByID").(bool)

		if failDBLog {
			return errors.New("Error Update Device Certificate Serial Number By ID")
		}
	} else {
		if id == "errorUpdateDeviceCertificateSerialNumberByID" {
			return errors.New("error")
		}
		return nil
	}
	return nil
}

func (db *MockDB) UpdateDeviceCertHistory(ctx context.Context, deviceId string, serialNumber string, newStatus string) error {
	if deviceId != device.Id {
		return errors.New("error")
	}
	return nil
}
func (db *MockDB) DeleteDevice(ctx context.Context, id string) error {
	if id != device.Id {
		return errors.New("error")
	}
	return nil
}

func (db *MockDB) InsertLog(ctx context.Context, l dto.DeviceLog) error {
	if ctx.Value("DBInsertLog") != nil {
		failDBLog := ctx.Value("DBInsertLog").(bool)

		if failDBLog {
			return ErrInsertLog
		}
	} else {
		if l.DeviceId == "errorLog" {
			return ErrInsertLog
		} else {
			return nil
		}
	}
	return nil
}
func (db *MockDB) SelectDeviceLogs(ctx context.Context, deviceId string) ([]dto.DeviceLog, error) {
	var d []dto.DeviceLog
	if deviceId == "errorGetDeviceLogs" {
		notFoundErr := &devmanagererrors.ResourceNotFoundError{
			ResourceType: "DEVICE-LOGS",
			ResourceId:   deviceId,
		}
		return []dto.DeviceLog{}, notFoundErr
	} else if deviceId == "1" {
		log := dto.DeviceLog{Id: "1", DeviceId: "1", LogType: "log_type", LogMessage: "", Timestamp: ""}
		d = append(d, log)
		return d, nil
	} else {
		return d, nil
	}
}

func (db *MockDB) InsertDeviceCertHistory(ctx context.Context, l dto.DeviceCertHistory) error {
	if ctx.Value("DBInsertDeviceCertHistory") != nil {
		failDB := ctx.Value("DBInsertDeviceCertHistory").(bool)

		if failDB {
			return errors.New("Testing DB connection failed")
		} else {
			return nil
		}
	} else {
		return nil
	}
}
func (db *MockDB) SelectDeviceCertHistory(ctx context.Context, deviceId string) ([]dto.DeviceCertHistory, error) {

	certList := testGetDeviceCertHistory()
	for _, element := range certList {
		if element.DeviceId == deviceId {
			var array []dto.DeviceCertHistory
			array = append(array, element)
			return array, nil
		}
	}
	notFoundErr := &devmanagererrors.ResourceNotFoundError{
		ResourceType: "DEVICE-CERT HISTORY",
		ResourceId:   deviceId,
	}
	return []dto.DeviceCertHistory{}, notFoundErr

}
func (db *MockDB) SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (dto.DeviceCertHistory, error) {
	notFoundErr := &devmanagererrors.ResourceNotFoundError{
		ResourceType: "DEVICE-CERT HISTORY",
		ResourceId:   serialNumber,
	}
	if ctx.Value("DBSelectDeviceCertHistoryBySerialNumberFail") != nil {
		failDB := ctx.Value("DBSelectDeviceCertHistoryBySerialNumberFail").(bool)
		if failDB {
			return dto.DeviceCertHistory{}, notFoundErr
		}
	}
	certList := testGetDeviceCertHistory()
	for _, element := range certList {
		if element.SerialNumber == serialNumber {
			return element, nil
		}
	}
	return dto.DeviceCertHistory{}, notFoundErr

}
func (db *MockDB) SelectDeviceCertHistoryLastThirtyDays(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DeviceCertHistory, error) {
	if ctx.Value("DBSelectDeviceCertHistoryBySerialNumberFail") != nil {
		failDB := ctx.Value("DBSelectDeviceCertHistory").(bool)

		if failDB {
			var a []dto.DeviceCertHistory
			return a, errors.New("Testing DB connection failed")
		} else {
			return testGetDeviceCertHistory(), nil
		}
	} else {
		return testGetDeviceCertHistory(), nil
	}
}
func (db *MockDB) SetKeyAndSubject(ctx context.Context, keyMetadate dto.PrivateKeyMetadataWithStregth, subject dto.Subject, deviceId string) error {
	return nil
}
func (db *MockDB) UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error {
	if ctx.Value("DBUpdateStatus") != nil {
		if ctx.Value("DBUpdateStatus") != nil {
			failDBLog := ctx.Value("DBUpdateStatus").(bool)

			if failDBLog {
				notFoundErr := &devmanagererrors.ResourceNotFoundError{
					ResourceType: "DEVICE",
					ResourceId:   id,
				}
				return notFoundErr
			}
		} else {
			if id == "errorUpdateStatus" {
				notFoundErr := &devmanagererrors.ResourceNotFoundError{
					ResourceType: "DEVICE",
					ResourceId:   id,
				}
				return notFoundErr
			}
			return nil
		}
	} else {
		if id == "errorUpdateStatus" {
			notFoundErr := &devmanagererrors.ResourceNotFoundError{
				ResourceType: "DEVICE",
				ResourceId:   id,
			}
			return notFoundErr
		}
		return nil
	}
	return nil
}

func (db *MockDB) SelectDmssLastIssuedCert(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMSLastIssued, error) {
	if ctx.Value("DBSelectDmssLastIssuedCert") != nil {
		failDB := ctx.Value("DBSelectDmssLastIssuedCert").(bool)

		if failDB {
			var a []dto.DMSLastIssued
			return a, errors.New("Testing DB connection failed")
		} else {

			return testDmsLastIssuedCert(), nil
		}
	} else {

		return testDmsLastIssuedCert(), nil
	}
}

func testDevice() dto.Device {
	subject := dto.Subject{
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
		Organization:     "Lamassu",
		OrganizationUnit: "IoT",
		CommonName:       "testDeviceMock",
	}
	key := dto.PrivateKeyMetadataWithStregth{
		KeyType:     "RSA",
		KeyBits:     3072,
		KeyStrength: "low",
	}
	device := dto.Device{
		Id:                    "1",
		Alias:                 "testDeviceMock",
		Status:                "CERT_REVOKED",
		DmsId:                 "1",
		Subject:               subject,
		KeyMetadata:           key,
		CreationTimestamp:     "2022-01-11T07:02:40.082286Z",
		ModificationTimestamp: "2022-01-11T07:02:40.082286Z",
	}
	device.CurrentCertificate.SerialNumber = "1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87"
	return device
}
func testDeviceNoSerialNumber() dto.Device {
	subject := dto.Subject{
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Arrasate",
		Organization:     "Lamassu",
		OrganizationUnit: "IoT",
		CommonName:       "testDeviceMock",
	}
	key := dto.PrivateKeyMetadataWithStregth{
		KeyType:     "RSA",
		KeyBits:     3072,
		KeyStrength: "",
	}
	device := dto.Device{
		Id:                "1",
		Alias:             "noSN",
		Status:            "CERT_REVOKED",
		DmsId:             "1",
		Subject:           subject,
		KeyMetadata:       key,
		CreationTimestamp: "2022-01-11T07:02:40.082286Z",
	}

	return device
}

func testDeviceLogs() []dto.DeviceLog {

	var logList []dto.DeviceLog
	log := dto.DeviceLog{
		Id:         "1",
		DeviceId:   "1",
		LogType:    "",
		LogMessage: "",
		Timestamp:  "",
	}
	logList = append(logList, log)
	return logList
}

func testDmsLastIssuedCert() []dto.DMSLastIssued {
	var certList []dto.DMSLastIssued
	cert := dto.DMSLastIssued{
		DmsId:             "1",
		CreationTimestamp: "",
		SerialNumber:      "",
	}
	certList = append(certList, cert)
	return certList
}

func testGetDeviceCertHistory() []dto.DeviceCertHistory {

	var certList []dto.DeviceCertHistory
	cert := dto.DeviceCertHistory{

		DeviceId:          "1",
		SerialNumber:      "1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87",
		IsuuerName:        "",
		Status:            "",
		CreationTimestamp: "",
	}
	certList = append(certList, cert)
	return certList
}
