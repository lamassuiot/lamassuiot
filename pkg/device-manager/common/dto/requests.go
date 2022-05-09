package dto

type CreateDeviceRequest struct {
	DeviceID    string   `json:"id" validate:"required"`
	Alias       string   `json:"alias"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	IconName    string   `json:"icon_name"`
	IconColor   string   `json:"icon_color"`
	DmsId       string   `json:"dms_id" validate:"required"`
}

type UpdateDevicesByIdRequest struct {
	DeviceID    string   `json:"id" validate:"required"`
	Alias       string   `json:"alias"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	IconName    string   `json:"icon_name"`
	IconColor   string   `json:"icon_color"`
	DmsId       string   `json:"dms_id" `
}
