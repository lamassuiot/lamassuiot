package resources

import "github.com/lamassuiot/lamassuiot/pkg/v3/models"

type CreateDeviceBody struct {
	ID        string         `json:"id"`
	Alias     string         `json:"alias"`
	Tags      []string       `json:"tags"`
	Metadata  map[string]any `json:"metadata"`
	DMSID     string         `json:"dms_id"`
	Icon      string         `json:"icon"`
	IconColor string         `json:"icon_color"`
}

type UpdateDeviceMetadataBody struct {
	Metadata map[string]any `json:"metadata"`
}

type UpdateDeviceIdentitySlotBody struct {
	models.Slot[models.Certificate]
}
