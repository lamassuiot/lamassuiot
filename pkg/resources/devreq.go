package resources

import (
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
)

var DeviceFiltrableFields = map[string]FilterFieldType{
	"id":                 StringFilterFieldType,
	"dms_owner":          StringFilterFieldType,
	"creation_timestamp": DateFilterFieldType,
	"status":             EnumFilterFieldType,
	"tags":               StringArrayFilterFieldType,
}

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
	NewStatus models.DeviceStatus `json:"new_status"`
}

type UpdateDeviceMetadataBody struct {
	Metadata map[string]any `json:"metadata"`
}

type CreateDeviceEventBody struct {
	Timestamp        time.Time              `json:"timestamp"`
	Type             models.DeviceEventType `json:"type"`
	Description      string                 `json:"description"`
	Source           string                 `json:"source"`
	Status           models.DeviceStatus    `json:"status"`
	StructuredFields map[string]any         `json:"structured_fields"`
}
