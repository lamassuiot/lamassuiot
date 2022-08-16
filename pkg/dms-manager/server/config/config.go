package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port     string `required:"true" split_words:"true"`
	Protocol string `required:"true" split_words:"true"`

	PostgresUser     string `required:"true" split_words:"true"`
	PostgresDB       string `required:"true" split_words:"true"`
	PostgresPassword string `required:"true" split_words:"true"`
	//PostgresDevicesDB string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	MutualTLSEnabled  bool   `split_words:"true"`
	MutualTLSClientCA string `split_words:"true"`

	LamassuCACertFile string `split_words:"true"`
	LamassuCAAddress  string `split_words:"true"`

	DebugMode string `required:"true" split_words:"true"`

	CertFile string `split_words:"true"`
	KeyFile  string `split_words:"true"`

	OpenapiEnableSecuritySchema     bool   `required:"true" split_words:"true"`
	OpenapiSecurityOidcWellKnownUrl string `split_words:"true"`
}

func NewConfig(prefix string) (error, Config) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return err, Config{}
	}
	return nil, cfg
}
