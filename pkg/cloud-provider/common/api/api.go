package api

import (
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type CAConfiguration struct {
	CAName        string
	Configuration interface{}
}

//------------------------------------------------------

type GetConfigurationInput struct{}

type GetConfigurationOutput struct {
	Configuration    interface{}
	CAsConfiguration []CAConfiguration
}

//------------------------------------------------------

type UpdateConfigurationInput struct {
	Configuration interface{}
}

type UpdateConfigurationOutput struct {
	Configuration interface{}
}

//------------------------------------------------------

type GetDeviceConfigurationInput struct {
	DeviceID string
}

type GetDeviceConfigurationOutput struct {
	Configuration interface{}
}

//------------------------------------------------------

type RegisterCAInput struct {
	models.CACertificate
}

type RegisterCAOutput struct{}

//------------------------------------------------------

type UpdateCAStatusInput struct {
	CAName string
	Status string
}

type UpdateCAStatusOutput struct{}

//------------------------------------------------------

type UpdateDeviceCertificateStatusInput struct {
	DeviceID     string
	CAName       string
	SerialNumber string
	Status       string
}

type UpdateDeviceCertificateStatusOutput struct{}

// ------------------------------------------------------
type UpdateDeviceDigitalTwinReenrollmentStatusInput struct {
	DeviceID      string
	SlotID        string
	ForceReenroll bool
}

type UpdateDeviceDigitalTwinReenrollmentStatusOutput struct{}

//------------------------------------------------------

type UpdateDMSCaCertsInput struct {
	dmsApi.DeviceManufacturingService
}

type UpdateDMSCaCertsOutput struct{}

//------------------------------------------------------
