package config

type DMSconfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CAClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	DevManagerClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	DownstreamCertificateFile string `mapstructure:"downstream_cert_file"`

	DeviceMonitorConfig `mapstructure:"device_monitoring"`
}

type DeviceMonitorConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Frequency string `mapstructure:"frequency"`
}
