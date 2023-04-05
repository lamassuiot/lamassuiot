package config

type DeviceManagerConfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CAClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	DMSManagerClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"dms_manager_client"`
}
