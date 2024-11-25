package resources

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type CreateDMSBody struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Metadata map[string]any     `json:"metadata"`
	Settings models.DMSSettings `json:"settings"`
}

type BindIdentityToDeviceBody struct {
	BindMode                models.DeviceEventType `json:"bind_mode"`
	DeviceID                string                 `json:"device_id"`
	CertificateSerialNumber string                 `json:"certificate_serial_number"`
}
