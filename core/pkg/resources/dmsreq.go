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

// UpdateDMSBody is the payload of PUT /v1/dms/:id. The DMS ID is taken from the
// URL path (the one evaluated by authz), so it is intentionally not part of the body.
// PUT replaces the DMS, so name and settings are mandatory; an omitted metadata clears it.
// Settings is a pointer so that an omitted value can be told apart from an empty one.
type UpdateDMSBody struct {
	Name     string              `json:"name" binding:"required"`
	Metadata map[string]any      `json:"metadata"`
	Settings *models.DMSSettings `json:"settings" binding:"required"`
}

type BindIdentityToDeviceBody struct {
	BindMode                models.DeviceEventType `json:"bind_mode"`
	DeviceID                string                 `json:"device_id"`
	CertificateSerialNumber string                 `json:"certificate_serial_number"`
}

type UpdateDMSMetadataBody struct {
	Patches []models.PatchOperation `json:"patches"`
}
