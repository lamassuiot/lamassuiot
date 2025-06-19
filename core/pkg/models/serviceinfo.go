package models

type APIServiceInfo struct {
	Version   string
	BuildSHA  string
	BuildTime string
}

type ServiceName string

const (
	CAServiceName            ServiceName = "ca"
	DMSManagerServiceName    ServiceName = "dms-manager"
	DeviceManagerServiceName ServiceName = "device-manager"
	AlertManagerServiceName  ServiceName = "alert-manager"
	VAServiceName            ServiceName = "va"
)
