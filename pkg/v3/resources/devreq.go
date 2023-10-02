package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type CreateDeviceBody struct {
	ID                 string            `json:"id"`
	Alias              string            `json:"alias"`
	Tags               []string          `json:"tags"`
	ConnectionMetadata map[string]string `json:"connection_metadata"`
	Metadata           map[string]string `json:"metadata"`
	DMSID              string            `json:"dms_id"`
	Icon               string            `json:"icon"`
	IconColor          string            `json:"icon_color"`
}

type UpdateIdentitySlotBody struct {
	models.Slot[models.Certificate]
}
