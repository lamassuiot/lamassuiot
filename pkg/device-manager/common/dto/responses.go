package dto

type GetDevicesResponse struct {
	TotalDevices int      `json:"total_devices"`
	Devices      []Device `json:"devices,omitempty"`
}
type GetLogsResponse struct {
	TotalLogs int         `json:"total_logs"`
	Logs      []DeviceLog `json:"logs,omitempty"`
}

type GetLastIssuedCertResponse struct {
	TotalLastIssuedCert int             `json:"total_last_issued_cert"`
	IssuedCert          []DMSLastIssued `json:"dms_last_issued_cert,omitempty"`
}
