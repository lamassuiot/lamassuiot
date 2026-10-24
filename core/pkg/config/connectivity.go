package config

type BasicConnection struct {
	Hostname  string `mapstructure:"hostname" json:"hostname,omitempty"`
	Port      int    `mapstructure:"port" json:"port,omitempty"`
	TLSConfig `mapstructure:",squash"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify"`
	CACertificateFile  string `mapstructure:"ca_cert_file" json:"ca_cert_file,omitempty"`
}
