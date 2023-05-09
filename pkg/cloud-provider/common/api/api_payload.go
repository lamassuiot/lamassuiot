package api

import (
	caApi "github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
)

type UpdateDeviceCertificateStatusPayload struct {
	CAName       string `json:"ca_name"`
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
}

type RegisterCAPayload struct {
	caApi.CACertificateSerialized
}

type UpdateDeviceDigitalTwinReenrollmentStatusPayload struct {
	SlotID        string `json:"slot_id"`
	ForceReenroll bool   `json:"force_reenroll"`
}

type UpdateDMSCaCertPayload struct {
	dmsApi.DeviceManufacturingServiceSerialized
}
