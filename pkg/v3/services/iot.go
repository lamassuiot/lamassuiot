package services

type IoTService[CloudConfig any, DeviceConfig any] interface {
	GetCloudProviderConfig() (*CloudConfig, error)
	GetDeviceConfiguration(input *GetDeviceConfigurationInput) (*DeviceConfig, error)
}

type GetDeviceConfigurationInput struct {
	DeviceID string
}
