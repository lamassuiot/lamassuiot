package dto

type GetDevicesResponse struct {
	TotalDevices int      `json:"total_devices"`
	Devices      []Device `json:"devices,omitempty"`
}
