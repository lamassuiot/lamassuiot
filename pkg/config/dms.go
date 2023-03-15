package config

type DMSconfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CAClient struct {
		HTTPConnection
	} `mapstructure:"ca_client"`

	DownstreamCertificateFile string `mapstructure:"downstream_cerificate_file"`
}
