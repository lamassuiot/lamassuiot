package mocks

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	devicesModel "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"

	//devicesStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/models/device/store"

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

func (db *MockDB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {
	return "", nil
}
func (db *MockDB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	return nil, nil
}
func (db *MockDB) UpdateByID(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error {
	return nil
}

func (db *MockDB) InsertDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error {
	if deviceID == "error" {
		return errors.New("error")

		/*dbT, mock, err := sqlmock.New()
		if err != nil {
			return err
		}
		defer dbT.Close()

		sqlStatement := `
		INSERT INTO device_information(id, alias, status, dms_id,country, state ,locality ,organization ,organization_unit, common_name, key_type, key_bits, key_stregnth, current_cert_serial_number, creation_ts)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id;
		`
		n, err := strconv.ParseInt(d.Id, 10, 64)
		mock.ExpectBegin()
		mock.ExpectExec(sqlStatement).WithArgs(d.Id,
			d.Alias,
			dto.DevicePendingProvision,
			d.DmsId,
			d.Country,
			d.State,
			d.Locality,
			d.Organization,
			d.OrganizationUnit,
			d.CommonName,
			d.KeyType,
			d.KeyBits,
			d.KeyStrength,
			"",
			time.Now()).WillReturnResult(sqlmock.NewResult(n, 1))
		mock.ExpectCommit()

		if err != nil {
			level.Error(db.logger).Log("err", err, "msg", "Could not insert device with ID "+d.Id+" in database")
			return err
		}*/
	} else {
		//level.Info(db.logger).Log("msg", "Device with ID "+d.Id+" inserted in database")

		//dev := dto.Device{}
		return nil
	}
}

func (db *MockDB) SelectDeviceById(ctx context.Context, id string) (dto.Device, error) {
	dev := testDevice()
	if ctx.Value("DBSelectDeviceById") != nil {
		failDBLog := ctx.Value("DBSelectDeviceById").(bool)

		if failDBLog {
			return dev, errors.New("Error finding device")
		} else {
			if id == "errorDeviceById" {
				return dev, ErrDeviceById

				/*} else if id == "errorLog" {
				return dev, errors.New("Could not insert log")
				*/
			} else if id == "noSerialNumber" {
				dev := testDeviceNoSerialNumber()
				return dev, ErrSerialNumber

			} else if id == "decommisioned" {
				dev.Status = devicesModel.DeviceDecommisioned.String()
				return dev, nil
			} else if id == "provisioned" || id == "DEVICE" {
				if ctx.Value("DBDecommisioned") != nil {
					failDB := ctx.Value("DBDecommisioned").(bool)

					if failDB {
						dev.Status = devicesModel.DeviceCertRevoked.String()
					} else {
						dev.Status = devicesModel.DeviceProvisioned.String()
					}
				} else {

					dev.Status = devicesModel.DeviceProvisioned.String()
				}
				return dev, nil

			} else {

				return dev, nil
			}
		}
	} else {
		if id == "errorDeviceById" {
			return dev, ErrDeviceById

			/*} else if id == "errorLog" {
			return dev, errors.New("Could not insert log")
			*/
		} else if id == "noSerialNumber" {
			dev := testDeviceNoSerialNumber()
			return dev, ErrSerialNumber

		} else if id == "decommisioned" {
			dev.Status = devicesModel.DeviceDecommisioned.String()
			return dev, nil
		} else if id == "provisioned" || id == "DEVICE" {

			if ctx.Value("DBDecommisioned") != nil {
				failDB := ctx.Value("DBSelectDeviceById").(bool)

				if failDB {
					dev.Status = devicesModel.DeviceCertRevoked.String()
				} else {
					dev.Status = devicesModel.DeviceProvisioned.String()
				}
			} else {
				dev.Status = devicesModel.DeviceProvisioned.String()
			}
			return dev, nil

		} else {

			return dev, nil
		}
	}

}

func (db *MockDB) SelectAllDevices(ctx context.Context, queryParameters dto.QueryParameters) ([]dto.Device, int, error) {
	failDB := ctx.Value("DBShouldFail").(bool)

	if failDB {
		var a []dto.Device
		return a, 0, errors.New("Testing DB connection failed")
	} else {
		var devList []dto.Device
		var d dto.Device
		d = testDevice()
		devList = append(devList, d)
		return devList, 0, nil
	}

}
func (db *MockDB) SelectAllDevicesByDmsId(ctx context.Context, dms_id string, queryParameters dto.QueryParameters) ([]dto.Device, error) {

	var devList []dto.Device
	var d dto.Device
	d = testDevice()
	devList = append(devList, d)

	if dms_id == "error" {
		var a []dto.Device
		return a, ErrDeviceById
	}
	return devList, nil
}

/*func (db *MockDB) UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error {
	if ctx.Value("DBUpdateStatus") != nil {
		failDBLog := ctx.Value("DBUpdateStatus").(bool)

		if failDBLog {
			return errors.New("Error Update Status")
		}
	} else {
		if id == "errorUpdateStatus" {
			return errors.New("error")
		}
		return nil
	}
	return nil
}*/
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
	if deviceId == "errorUpdateDeviceCertHistory" {
		return errors.New("error")
	}
	return nil
}
func (db *MockDB) DeleteDevice(ctx context.Context, id string) error {
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
		return testDeviceLogs(), errors.New("err")
	} else {
		return d, nil
	}

}

func (db *MockDB) InsertDeviceCertHistory(ctx context.Context, l dto.DeviceCertHistory) error {
	failDB := ctx.Value("DBInsertDeviceCertHistory").(bool)

	if failDB {
		return errors.New("Testing DB connection failed")
	} else {
		return nil
	}
}
func (db *MockDB) SelectDeviceCertHistory(ctx context.Context, deviceId string) ([]dto.DeviceCertHistory, error) {
	failDB := ctx.Value("DBSelectDeviceCertHistory").(bool)

	if failDB {
		var a []dto.DeviceCertHistory
		return a, errors.New("Testing DB connection failed")
	} else {
		return testGetDeviceCertHistory(), nil
	}
}
func (db *MockDB) SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (dto.DeviceCertHistory, error) {
	failDB := ctx.Value("DBSelectDeviceCertHistoryBySerialNumberFail").(bool)

	if failDB {
		return dto.DeviceCertHistory{}, errors.New("Testing DB connection failed")
	} else {
		return testGetDeviceCertHistory()[0], nil
	}
}
func (db *MockDB) SelectDeviceCertHistoryLastThirtyDays(ctx context.Context, queryParameters dto.QueryParameters) ([]dto.DeviceCertHistory, error) {
	failDB := ctx.Value("DBSelectDeviceCertHistory").(bool)

	if failDB {
		var a []dto.DeviceCertHistory
		return a, errors.New("Testing DB connection failed")
	} else {
		return testGetDeviceCertHistory(), nil
	}
}
func (db *MockDB) SetKeyAndSubject(ctx context.Context, keyMetadate dto.PrivateKeyMetadataWithStregth, subject dto.Subject, deviceId string) error {
	return nil
}
func (db *MockDB) UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error {
	return nil
}

func (db *MockDB) SelectDmssLastIssuedCert(ctx context.Context, queryParameters dto.QueryParameters) ([]dto.DMSLastIssued, error) {
	failDB := ctx.Value("DBSelectDmssLastIssuedCert").(bool)

	if failDB {
		var a []dto.DMSLastIssued
		return a, errors.New("Testing DB connection failed")
	} else {

		return testDmsLastIssuedCert(), nil
	}
}

func testDevice() dto.Device {
	subject := dto.Subject{
		C:  "ES",
		ST: "Guipuzcoa",
		L:  "Mondragon",
		O:  "Ikerlan",
		OU: "ZPD",
		CN: "testDeviceMock",
	}
	key := dto.PrivateKeyMetadataWithStregth{
		KeyType:     "RSA",
		KeyBits:     3072,
		KeyStrength: "",
	}
	device := dto.Device{
		Id:                "1",
		Alias:             "testDeviceMock",
		Status:            "CERT_REVOKED",
		DmsId:             "1",
		Subject:           subject,
		KeyMetadata:       key,
		CreationTimestamp: "2022-01-11T07:02:40.082286Z",
	}

	return device
}
func testDeviceNoSerialNumber() dto.Device {
	subject := dto.Subject{
		C:  "ES",
		ST: "Guipuzcoa",
		L:  "Mondragon",
		O:  "Ikerlan",
		OU: "ZPD",
		CN: "testDeviceMock",
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
		DmsId:        "1",
		Timestamp:    "",
		SerialNumber: "",
	}
	certList = append(certList, cert)
	return certList
}

func testGetDeviceCertHistory() []dto.DeviceCertHistory {

	var certList []dto.DeviceCertHistory
	cert := dto.DeviceCertHistory{

		DeviceId:          "1",
		SerialNumber:      "",
		IsuuerName:        "",
		Status:            "",
		CreationTimestamp: "",
	}
	certList = append(certList, cert)
	return certList
}
