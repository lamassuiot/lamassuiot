package api

import (
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
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
	caApi.CACertificate
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

//------------------------------------------------------
