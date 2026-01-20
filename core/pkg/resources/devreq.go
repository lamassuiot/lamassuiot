package resources

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type CreateDeviceBody struct {
	ID        string         `json:"id"`
	Alias     string         `json:"alias"`
	Tags      []string       `json:"tags"`
	Metadata  map[string]any `json:"metadata"`
	DMSID     string         `json:"dms_id"`
	Icon      string         `json:"icon"`
	IconColor string         `json:"icon_color"`
}

type UpdateDeviceIdentitySlotBody struct {
	models.Slot[string]
}

type UpdateDeviceMetadataBody struct {
	Patches []models.PatchOperation `json:"patches"`
}

type UpdateEventBody struct {
	EventData string `json:"event_data"`
}

type UpdateWFXStatusBody struct {
	WFXStatus string `json:"wfx_status"`
}
