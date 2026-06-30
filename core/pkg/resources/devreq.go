package resources

import (
	"time"

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

type CreateDeviceEventBody struct {
	// omitzero (Go 1.24+) is required here: stdlib `omitempty` has no effect on
	// time.Time because it's a struct, so the zero value would still be marshalled
	// as "0001-01-01T00:00:00Z" if a client encoded this struct directly.
	Timestamp        time.Time              `json:"event_ts,omitzero"`
	Type             models.DeviceEventType `json:"type"`
	Description      string                 `json:"description"`
	Source           string                 `json:"source"`
	StructuredFields map[string]any         `json:"structured_fields"`
}

// Device Group Request Bodies

// DeviceGroupFilterOptionRequest represents a filter criterion in the API request.
// Uses operand names (strings) instead of raw FilterOperation enums.
type DeviceGroupFilterOptionRequest struct {
	Field   string `json:"field"`
	Operand string `json:"operand"`
	Value   string `json:"value"`
}

type CreateDeviceGroupBody struct {
	ID          string                           `json:"id"`
	Name        string                           `json:"name"`
	Description string                           `json:"description"`
	ParentID    *string                          `json:"parent_id,omitempty"`
	Criteria    []DeviceGroupFilterOptionRequest `json:"criteria"`
}

type UpdateDeviceGroupBody struct {
	Name        string                           `json:"name"`
	Description string                           `json:"description"`
	ParentID    *string                          `json:"parent_id,omitempty"`
	Criteria    []DeviceGroupFilterOptionRequest `json:"criteria"`
}
