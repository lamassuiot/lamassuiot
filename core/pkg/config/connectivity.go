package config

type BasicConnection struct {
	Hostname  string `mapstructure:"hostname"`
	Port      int    `mapstructure:"port"`
	TLSConfig `mapstructure:",squash"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
	CACertificateFile  string `mapstructure:"ca_cert_file"`
}
