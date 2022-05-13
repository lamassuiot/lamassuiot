package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	CertFile string `required:"true" split_words:"true"`
	KeyFile  string `required:"true" split_words:"true"`

	OcspSignCert string `required:"true" split_words:"true"`
	OcspSignKey  string `required:"true" split_words:"true"`

	Port   string `required:"true" split_words:"true"`
	SSL    bool   `required:"true" split_words:"true"`
	Strict bool   `required:"true" split_words:"true"`

	LamassuCAAddress  string `split_words:"true"`
	LamassuCACertFile string `split_words:"true"`
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
