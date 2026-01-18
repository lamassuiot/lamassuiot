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
