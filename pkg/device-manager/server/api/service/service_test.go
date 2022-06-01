package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/go-kit/kit/log"

	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/mocks"
	devicesStore "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"

	"github.com/lamassuiot/lamassuiot/pkg/utils"
)

type serviceSetUp struct {
	devicesDb       devicesStore.DB
	logger          log.Logger
	lamassuCaClient lamassucaclient.LamassuCaClient
}

func TestPostDevice(t *testing.T) {
	srv, ctx := setup(t)

	device := testDevice()

	testCases := []struct {
		name string
		id   string
		err  error
	}{
		{"Correct device", "2", nil},
		{"Error Inserting Log", "2", errors.New("Could not insert log")},
		{"Error Inserting Device", "1", errors.New("resource already exists. resource_type=DEVICE resource_id=1")},
		{"Error Selecting Device", "2", errors.New("resource not found. resource_type=DEVICE resource_id=2")},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			tags := []string{"tag1", "tag2"}
			if tc.name == "Error Inserting Log" {
				ctx = context.WithValue(ctx, "DBInsertLog", true)
			} else {
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			}
			_, err := srv.PostDevice(ctx, device.Alias, tc.id, device.DmsId, "", tags, "", "")
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			}
		})
	}
}

func TestUpdateDeviceById(t *testing.T) {
	srv, ctx := setup(t)

	device := testDevice()
	deviceError := testDevice()
	deviceError.Id = "error"
	deviceErrorLog := device
	deviceErrorLog.Id = "errorLog"

	testCases := []struct {
		name string
		in   dto.Device
		err  error
	}{
		{"Correct device", device, nil},
		{"Error Inserting Log", deviceError, errors.New("No rows have been updated in database")},
		{"Error Select Device By Id", device, errors.New("resource not found. resource_type=DEVICE resource_id=1")},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Select Device By Id" {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", true)
			} else if tc.name == "Error getting devices" {
				ctx = context.WithValue(ctx, "DBInsertLog", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
			}
			tags := []string{"tag1", "tag2"}

			_, err := srv.UpdateDeviceById(ctx, tc.in.Alias, tc.in.Id, tc.in.DmsId, "", tags, "", "")
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			}
		})
	}
}
func TestGetDevices(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  error
	}{
		{"Error Get Cert", errors.New("Error getting certificate")},
		{"Correct", nil},
		{"Error getting devices", errors.New("Testing DB connection failed")},
		{"Error Cert SerialNumber", errors.New("resource not found. resource_type=DEVICE-CERT HISTORY resource_id=1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error getting devices" {
				ctx = context.WithValue(ctx, "DBShouldFail", true)
			} else if tc.name == "Error Cert SerialNumber" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
			} else if tc.name == "Error Get Cert" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBGetCert", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBGetCert", false)
			}
			_, _, err := srv.GetDevices(ctx, filters.QueryParameters{})
			if err != nil {
				if tc.ret.Error() != err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestGetStats(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
	}{
		{"Correct"},
		{"SelectAllDevicesError"},
		{"Error Update Stats"},
		{"Error Getting Stats"},
	}

	for _, tc := range testCases {

		if tc.name == "SelectAllDevicesError" {
			ctx = context.WithValue(ctx, "DBShouldFail", true)
		} else if tc.name == "Error Update Stats" {
			ctx = context.WithValue(ctx, "DBShouldFail", false)
			ctx = context.WithValue(ctx, "DBUpdateStats", true)
			ctx = context.WithValue(ctx, "DBGetStats", false)
		} else if tc.name == "Error Getting Stats" {
			ctx = context.WithValue(ctx, "DBGetStats", true)
		} else {
			ctx = context.WithValue(ctx, "DBShouldFail", false)
			ctx = context.WithValue(ctx, "DBUpdateStats", false)
			ctx = context.WithValue(ctx, "DBGetStats", false)
		}
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			srv.Stats(ctx)
		})
	}
}

func TestHealth(t *testing.T) {
	srv, ctx := setup(t)
	type testCasesHealth struct {
		name string
		ret  bool
	}
	cases := []testCasesHealth{
		{"Correct", true},
	}
	for _, tc := range cases {

		out := srv.Health(ctx)
		if tc.ret != out {
			t.Errorf("Expected '%s', but got '%s'", strconv.FormatBool(tc.ret), strconv.FormatBool(out))
		}
	}
}

func TestGetDeviceCert(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Error getting cert", "2", errors.New("Error getting certificate")},

		{"Error Select Device By Id", "error", errors.New("resource not found. resource_type=DEVICE resource_id=error")},
		{"Error Select Device Cert By Serial Number", "error", errors.New("resource not found. resource_type=DEVICE resource_id=error")},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error getting cert" {

				ctx = context.WithValue(ctx, "DBGetCert", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
			} else if tc.name == "Error Select Device Cert By Serial Number" {
				ctx = context.WithValue(ctx, "DBGetCert", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBDecommisioned", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)

			}
			_, err := srv.GetDeviceCert(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}

		})
	}
}

func TestGenerateCSR(t *testing.T) {
	_, ctx := setup(t)
	var p1 interface{}

	testCases := []struct {
		name    string
		keyType string
		ret     error
	}{
		{"Empty priv", "EC", errors.New("x509: certificate private key does not implement crypto.Signer")},
		{"Empty priv", "RSA", errors.New("x509: certificate private key does not implement crypto.Signer")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			_, err := _generateCSR(ctx, tc.keyType, p1, "commonName", "country", "state", "locality", "org", "orgUnit")
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", tc.ret, err)
				}
			}
		})
	}
}

func TestGetDeviceById(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Incorrect", "errorDeviceById", errors.New("resource not found. resource_type=DEVICE resource_id=errorDeviceById")},
		{"Error Get Certificate", "1", errors.New("Error getting certificate")},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Get Certificate" {
				ctx = context.WithValue(ctx, "DBGetCert", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			} else {
				ctx = context.WithValue(ctx, "DBGetCert", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			}

			_, err := srv.GetDeviceById(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", tc.ret, err)
				}
			}
		})
	}
}

func TestGetDevicesByDMS(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name  string
		dmsId string
		ret   error
	}{
		{"Incorrect", "error", errors.New("resource not found. resource_type=DEVICE resource_id=error")},
		{"Error Get Certificate", "1", errors.New("Error getting certificate")},
		{"Select Device Cert History By Serial Number", "1", errors.New("resource not found. resource_type=DEVICE-CERT HISTORY resource_id=1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87")},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Select Device Cert History By Serial Number" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
			} else if tc.name == "Error Get Certificate" {
				ctx = context.WithValue(ctx, "DBGetCert", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			} else {
				ctx = context.WithValue(ctx, "DBGetCert", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			}
			_, err := srv.GetDevicesByDMS(ctx, tc.dmsId, filters.QueryParameters{})
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", tc.ret, err)
				}
			}
		})
	}
}

func TestGetDeviceLogs(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Incorrect", "errorGetDeviceLogs", errors.New("resource not found. resource_type=DEVICE-LOGS resource_id=errorGetDeviceLogs")},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			_, err := srv.GetDeviceLogs(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestGetDeviceCertHistory(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Error Device Certification History", "error", errors.New("resource not found. resource_type=DEVICE-CERT HISTORY resource_id=error")},
		{"Error Select Device By Id", "1", errors.New("resource not found. resource_type=DEVICE resource_id=1")},
		{"Error Get Cert By Id", "1", errors.New("Error getting certificate")},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Device Certification History" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBGetCert", false)
			} else if tc.name == "Error Select Device By Id" {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", true)
				ctx = context.WithValue(ctx, "DBGetCert", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
			} else if tc.name == "Error Get Cert By Id" {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBGetCert", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBGetCert", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
			}
			_, err := srv.GetDeviceCertHistory(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestGetDmsCertHistoryThirtyDays(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  error
	}{
		{"Error Get Devices", errors.New("Testing DB connection failed")},
		{"Error getting historial 30 days", errors.New("Testing DB connection failed")},
		{"Correct", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error getting historial 30 days" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", true)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
			} else if tc.name == "Error Get Devices" {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "DBShouldFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistory", false)
				ctx = context.WithValue(ctx, "DBShouldFail", false)
			}
			_, err := srv.GetDmsCertHistoryThirtyDays(ctx, filters.QueryParameters{})
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestGetDmsLastIssuedCert(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  error
	}{
		{"Error last issued cert not found", errors.New("Testing DB connection failed")},
		{"Correct", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error last issued cert not found" {
				ctx = context.WithValue(ctx, "DBSelectDmssLastIssuedCert", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectDmssLastIssuedCert", false)
			}
			_, err := srv.GetDmsLastIssuedCert(ctx, filters.QueryParameters{})
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestRevokeDeviceCert(t *testing.T) {
	srv, ctx := setup(t)
	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Error finding device", "error", errors.New("resource not found. resource_type=DEVICE resource_id=error")},
		{"Error inserting log", "1", errors.New("Could not insert log")},
		{"Error empty serial number", "noSerialNumber", errors.New("No Serial Number")},
		{"Error could not revoke certificate", "1", errors.New("Error revoking certificate")},
		{"Error updating certificate history serial number", "1", errors.New("resource not found. resource_type=DEVICE-CERT HISTORY resource_id=1E-6A-EC-C2-05-64-EF-65-66-7F-5B-AE-7B-B4-15-25-19-E8-2C-87")},
		{"Error updating device status", "1", errors.New("no rows have been updated in database")},
		{"Resource not found", "error", errors.New("resource not found. resource_type=DEVICE resource_id=error")},
		{"Correct", "1", nil},
		{"Error Update Device Certificate Status By ID", "1", errors.New("Error Update Device Certificate Serial Number By ID")},
		{"Error Update Device Status By ID", "1", errors.New("resource not found. resource_type=DEVICE resource_id=1")},
	}

	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error certificate history could not find" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)

			} else if tc.name == "Error inserting log" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)

			} else if tc.name == "Error could not revoke certificate" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBInsertLog", false)
			} else if tc.name == "Error updating certificate history serial number" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", true)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
			} else if tc.name == "Error Update Device Status By ID" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", true)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", true)
			} else if tc.name == "Error Update Device Certificate Status By ID" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "DBUpdateStatus", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "DBUpdateDeviceCertificateSerialNumberByID", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceById", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			}

			err := srv.RevokeDeviceCert(ctx, tc.id, "Manual revocation")

			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestDeleteDevice(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{
		{"Error finding device", "error", errors.New("test")},
		{"Error inserting log", "errorLog", errors.New("Could not insert log")},
		{"Error empty serial number", "error", errors.New("test")},
		{"Error could not revoke certificate", "errorRevokeCert", errors.New("test")},
		{"Error updating certificate history", "errorUpdateDeviceCertHistory", errors.New("test")},
		{"Error updating certificate history serial number", "errorUpdateDeviceCertificateSerialNumberByID", errors.New("test")},
		{"Error updating device status", "errorUpdateStatus", errors.New("resource not found. resource_type=DEVICE resource_id=errorUpdateStatus")},
		{"Error certificate history could not find", "error", errors.New("test")},
		{"Correct", "1", nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Error updating device status" {
				ctx = context.WithValue(ctx, "DBShouldFail", true)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)

			} else if tc.name == "Error certificate history could not find" {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", true)
			} else {
				ctx = context.WithValue(ctx, "DBShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "DBSelectDeviceCertHistoryBySerialNumberFail", false)
			}
			err := srv.DeleteDevice(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
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
		Id:                "noSN",
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

type Subject struct {
	CN string `json:"common_name"`
	O  string `json:"organization"`
	OU string `json:"organization_unit"`
	C  string `json:"country"`
	ST string `json:"state"`
	L  string `json:"locality"`
}

func testGetDeviceCert() dto.DeviceCert {

	subject := dto.Subject{
		Country:          "",
		State:            "",
		Locality:         "",
		Organization:     "",
		OrganizationUnit: "",
		CommonName:       "",
	}
	log := dto.DeviceCert{
		DeviceId:     "1",
		SerialNumber: "",
		CAName:       "",
		Status:       "",
		CRT:          "",
		Subject:      subject,
		ValidFrom:    "",
		ValidTo:      "",
	}
	return log
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

func testDMSCertsHistory() []dto.DMSCertHistory {

	var certList []dto.DMSCertHistory
	cert := dto.DMSCertHistory{
		DmsId:       "1",
		IssuedCerts: 1,
	}
	certList = append(certList, cert)
	return certList
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

func setup(t *testing.T) (Service, context.Context) {
	t.Helper()

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	ctx := context.Background()
	ctx = context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)

	devicesDb, _ := mocks.NewDevicedDBMock(t)
	statsDB, _ := mocks.NewInMemoryMockDB()

	lamassuCaClient, _ := mocks.NewLamassuCaClientMock(logger)

	srv := NewDevicesService(devicesDb, statsDB, &lamassuCaClient, logger)
	return srv, ctx
}
