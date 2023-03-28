package config

type DMSconfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CAClient struct {
		HTTPClient
	} `mapstructure:"ca_client"`

	DownstreamCertificateFile string `mapstructure:"downstream_cert_file"`
}
