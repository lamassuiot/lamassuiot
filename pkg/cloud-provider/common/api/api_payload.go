package api

import (
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
)

type UpdateDeviceCertificateStatusPayload struct {
	CAName       string `json:"ca_name"`
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
}

type RegisterCAPayload struct {
	models.CACertificate
}

type UpdateDeviceDigitalTwinReenrollmentStatusPayload struct {
	SlotID        string `json:"slot_id"`
	ForceReenroll bool   `json:"force_reenroll"`
}

type UpdateDMSCaCertPayload struct {
	dmsApi.DeviceManufacturingServiceSerialized
}
